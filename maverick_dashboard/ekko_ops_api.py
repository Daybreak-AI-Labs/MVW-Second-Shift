"""Run an Ekko recorder from the app (``maverick ekko run``).

The dashboard supports an uploaded guided activity file. The desktop recorder
must be started locally with the CLI until the dashboard can authenticate the
owner of the observed desktop. Both feed :class:`maverick.ekko_daemon.EkkoDaemon`, which keeps
every existing check: the device's current enrollment, the administrator's
limits, the exclusive recorder lease and the emergency stop.

Access matches the Ekko page's session controls: ``operate``, the same-origin
guard, and a store scoped to the signed-in person and selected workspace, with
a device chosen inside that scope. Starting a recorder writes the same
required "start authorized" audit row the command writes. Recording runs as a
background job; the page's Pause and Stop buttons end it.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from maverick import config
from maverick.governed_operations import digest

from . import auth

router = APIRouter(tags=["ekko"])
MAX_FILE_CHARS = 1_000_000


class ImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field("local-device", min_length=1, max_length=64)
    events: str = Field(min_length=1, max_length=MAX_FILE_CHARS)
    acknowledge_capture_scope: bool = False


def _access(request: Request) -> str:
    from maverick.paths import current_tenant_id_strict


    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        via = (getattr(principal, "claims", None) or {}).get("via")
        refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                   "proxy": auth._proxy_principal}.get(via)
        if refresh is not None:
            fresh = refresh(request)
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before opening the activity recorder.")
            request.state.principal = principal = fresh
        if principal is not None:
            auth._enforce_scim_active(principal)
            auth._enforce_workspace_policies(request, principal)
        auth.require_permission(request, "operate")
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Recording settings could not be read. Your choices are kept.")
        return digest([auth.caller_principal(request) or "", current_tenant_id_strict() or "",
                       auth.caller_role(request),
                       auth.has_global_permission(request, "admin"), config.get_ekko()])


def _prepare(request: Request, device_id: str, acknowledged: bool, observer: str):
    from maverick.audit import EventKind

    from . import ekko_routes as ekko

    ekko._require_same_origin(request)
    _access(request)
    if not acknowledged:
        raise HTTPException(400, "Confirm that you have read what Ekko may and may not record.")
    ekko._require_enabled_policy()
    store = ekko._store(request, device_id)
    policy = ekko._validated_enrolled_policy(store)
    if observer == "guided_jsonl" and policy.capture_level != "guided":
        raise HTTPException(409, "Activity files need detailed recording. An administrator can switch Ekko to "
                                 "detailed recording, then enroll this device again.")
    ekko._audit(EventKind.EKKO_SESSION, required=True, state="start_authorized",
                policy_digest=policy.fingerprint(), observer=observer)
    return store, policy


def _record(store, policy, observer) -> dict:
    import time

    from maverick.ekko_daemon import EkkoDaemon, GuidedJsonlObserver
    from maverick.ekko_foreground import ForegroundUnavailable

    daemon = EkkoDaemon(store=store, observer=observer, policy=policy)
    is_file = isinstance(observer, GuidedJsonlObserver) and observer.path is None
    deadline = time.monotonic() + 60 if is_file else None
    if is_file:
        observer.max_lines = 10_000
    limit_reached = False

    def stop_when() -> bool:
        nonlocal limit_reached
        if getattr(observer, "exhausted", False):
            return True
        if is_file and (observer.line_number >= observer.max_lines or time.monotonic() >= deadline):
            limit_reached = True
            return True
        return False

    try:
        daemon.run(
            stop_when=stop_when,
            max_idle_sleep=1.0 if is_file else None,
        )
    except ValueError as exc:
        line = getattr(observer, "line_number", 0)
        message = (f"Line {line} of the file isn't an activity Ekko can use. Activities recorded before it were kept."
                   if line else "The file couldn't be read as activities.")
        if "exceeds" in str(exc):
            message = f"Line {line} of the file is too long. Activities recorded before it were kept."
        return {"recorded": daemon.accepted_events, "skipped": daemon.blocked_events, "message": message}
    except ForegroundUnavailable:
        return {"recorded": daemon.accepted_events, "skipped": daemon.blocked_events,
                "message": "Desktop access ended or stopped responding. Recording has stopped. Activities already recorded were kept."}
    except RuntimeError:
        return {"recorded": daemon.accepted_events, "skipped": daemon.blocked_events,
                "message": "Recording stopped because this device's enrollment or limits changed."}
    finally:
        try:
            daemon.stop()
        finally:
            close = getattr(observer, "close", None)
            if callable(close):
                close()
    result = {"recorded": daemon.accepted_events, "skipped": daemon.blocked_events}
    if limit_reached:
        result["message"] = "Import stopped at its time or activity limit. Activities already recorded were kept."
    return result


@router.get("/api/v1/ekko/recording/options")
def recording_options(request: Request) -> dict:
    """Which recorders this installation can run."""
    from maverick.ekko_foreground import foreground_options

    authority = _access(request)
    options = foreground_options()
    if _access(request) != authority or foreground_options() != options:
        raise HTTPException(409, "Your account, workspace or recording settings changed. Open the current recording controls again.")
    # A dashboard request cannot establish that its requester owns the server's
    # desktop, especially behind a reverse proxy. Start this observer locally
    # through the CLI until a device-bound agent can prove that relationship.
    options = dict(options, active_app=False,
                   availability_message="Desktop recording runs from the recorder on the person's own computer.")
    return {"activity_file": True, "windows_active_app": False,
            "max_file_chars": MAX_FILE_CHARS, **options, "context": digest([authority, options])}


@router.post("/api/v1/ekko/recording/import", status_code=202)
def import_activity_file(request: Request, body: ImportIn) -> dict:
    """Record the activities in an uploaded guided activity file."""
    try:
        return _import_activity_file(request, body)
    except HTTPException as exc:
        raise HTTPException(exc.status_code, detail={"message": exc.detail, "not_started": True},
                            headers=exc.headers) from exc


def _import_activity_file(request: Request, body: ImportIn) -> dict:
    from maverick.ekko_daemon import GuidedJsonlObserver

    from .ops_jobs import JOBS, Busy, identity

    store, policy = _prepare(request, body.device_id, body.acknowledge_capture_scope, "guided_jsonl")
    observer = GuidedJsonlObserver.from_text(body.events)
    owner, tenant = identity(request)
    try:
        job = JOBS.start(owner=owner, tenant=tenant, kind="ekko-recording",
                         work=lambda: _record(store, policy, observer))
    except Busy as exc:
        observer.close()
        raise HTTPException(429, "A recording is already running. Wait for it to finish.") from exc
    return {"job": job}


@router.get("/api/v1/ekko/recording/{job_id}")
def recording_status(request: Request, job_id: str) -> dict:
    from .ops_jobs import JOBS, identity

    _access(request)
    owner, tenant = identity(request)
    job = JOBS.get(job_id[:64], owner=owner, tenant=tenant, kind="ekko-recording")
    if job is None:
        raise HTTPException(404, "no such recording")
    return job
