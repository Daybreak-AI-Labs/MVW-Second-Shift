"""REST API for Second Shift (mounted at /api/v1).

Goals run through the shared BackgroundTask runner in ``maverick.runner``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import stat
import time
from typing import NoReturn

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from . import step_up
from ._shared import _world
from ._shared import dashboard_token as _dashboard_token
from .api_schemas import ExternalAgentIn, ExternalCredentialIn, HaltIn, TrustRevokeIn
from .auth import (
    caller_principal,
    has_global_permission,
    require_global_permission,
    require_page_permission,
    require_permission,
)
from .halt_policy import shared_halt_backend as _shared_halt_backend

log = logging.getLogger(__name__)


router = APIRouter(prefix="/api/v1", tags=["v1"])


def _halt_backend_or_503() -> bool:
    try:
        return _shared_halt_backend()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="halt authority is unavailable",
        ) from exc


def _require_halt_permission(request: Request) -> bool:
    """Gate dashboard halt toggles at the correct blast radius.

    In local/SQLite mode the halt is process-local and remains an operator action.
    In shared Postgres mode the halt row is fleet-wide and untenanted, so toggling
    it is a global control-plane action reserved for dashboard admins.
    """
    shared = _halt_backend_or_503()
    if shared:
        require_global_permission(request, "admin")
    else:
        # The local HALT file is tenant=None and stops every tenant in this
        # process. A tenant-local role must not gain deployment-wide authority.
        require_global_permission(request, "operate")
    return shared


def _privacy_auth_genuinely_off() -> bool:
    from .request_identity import privacy_auth_genuinely_off

    return privacy_auth_genuinely_off(dashboard_token=_dashboard_token)


def _request_identity(request: Request) -> str | None:
    from .request_identity import request_identity

    return request_identity(
        request, caller=caller_principal, dashboard_token=_dashboard_token,
        auth_off=_privacy_auth_genuinely_off,
    )


def _request_actor(request: Request) -> str:
    from .request_identity import request_actor

    return request_actor(request, identity=_request_identity)


_HALT_DETAIL_MAX_BYTES = 8 * 1024
_HALT_REASON_MAX_CHARS = 200
_HALT_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HALT_AUDIT_HEADER = "X-Second-Shift-Audit-Written"


class _ConcurrentHalt(RuntimeError):
    """A newer local or shared HALT superseded an in-flight clear."""


def _bounded_halt_reason(reason: object, *, fallback: str) -> str:
    value = reason.strip() if isinstance(reason, str) else ""
    return (value or fallback)[:_HALT_REASON_MAX_CHARS]


def _publish_local_halt(
    path,
    *,
    actor: str,
    reason: str,
    scope: str,
    source: str,
) -> str:
    """Publish one private local stop without taking over a shared parent."""

    from maverick.file_lock import (
        atomic_write_text,
        cross_process_lock,
        prepare_private_directory,
    )
    from maverick.killswitch import (
        _file_halt_active,
        _halt_authority_lock_path,
        _halt_file_generation,
    )

    # ``MAVERICK_HALT_FILE`` is caller-selected.  Tightening an existing
    # parent can revoke unrelated services' access, so only create a missing
    # dedicated directory or require the existing parent to already be private.
    prepare_private_directory(path.parent)
    generation = secrets.token_urlsafe(24)
    with cross_process_lock(_halt_authority_lock_path(path), strict=True):
        local_detail = json.dumps(
            {
                "actor": actor,
                "created_at": time.time(),
                "generation": generation,
                "reason": _bounded_halt_reason(
                    reason,
                    fallback="manual via dashboard",
                ),
                "scope": scope,
                "source": source,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        atomic_write_text(path, local_detail + "\n", mode=0o600)
        if (
            _halt_file_generation(path) is None
            or not _file_halt_active(min_interval=0.0, fail_closed=True)
        ):
            raise RuntimeError("local HALT publication could not be verified")
    return generation


def _ensure_local_halt_fail_safe(
    path,
    *,
    actor: str,
    reason: str,
) -> str:
    """Preserve a concurrent local stop or publish compensation if absent."""

    from maverick.file_lock import cross_process_lock, prepare_private_directory
    from maverick.killswitch import (
        _halt_authority_lock_path,
        _halt_file_generation,
    )

    prepare_private_directory(path.parent)
    with cross_process_lock(_halt_authority_lock_path(path), strict=True):
        if _halt_file_generation(path) is not None:
            return "retained"
        _publish_local_halt(
            path,
            actor=actor,
            reason=reason,
            scope="local-compensation",
            source="dashboard-clear-compensation",
        )
        return "re-armed"


def _halt_workspace_audit(*, operation: str, actor: str, scope: str, reason: str) -> None:
    """Also show a completed stop or release in the acting workspace's log.

    The deployment-wide record above is the control-plane authority. Without
    this copy, the workspace's Activity log (what a person searches) had no
    trace that anyone engaged or released the emergency stop.
    """
    from maverick.audit import (
        AuditRefused,
        EventKind,
        audit_event,
        default_audit_log,
        global_audit_log,
    )

    try:
        if getattr(default_audit_log(), "audit_dir", None) == getattr(global_audit_log(), "audit_dir", None):
            return  # one chain: the deployment record is already this log's row
        # ``status`` is one of the fields the Activity log may show; the
        # reason is recorded but stays out of the summary view like any text.
        audit_event(EventKind.HALT, agent="dashboard", actor=actor, operation=operation,
                    status="released" if operation == "clear-halt" else "engaged",
                    scope=scope, reason=reason, detail=reason)
    except AuditRefused:
        # The stop itself is already applied and its deployment record governs.
        log.warning("workspace copy of the emergency stop record was refused", exc_info=True)
    except Exception:  # pragma: no cover -- audit_event is already fail-soft
        log.warning("workspace copy of the emergency stop record failed", exc_info=True)


def _halt_control_audit(
    *,
    operation: str,
    actor: str,
    scope: str,
    result: str,
    reason: str,
) -> bool:
    """Record one deployment-global, bounded HALT control-plane result.

    The shared audit helper propagates a configured ``AuditRefused`` posture
    and returns ``False`` for an ordinary fail-soft outage. Callers expose the
    latter in a response header and translate the former after describing the
    already-observed HALT state.
    """

    from maverick.audit import EventKind, audit_event

    bounded_reason = _bounded_halt_reason(
        reason,
        fallback="operator requested HALT state change",
    )
    if result == "succeeded":
        _halt_workspace_audit(operation=operation, actor=actor, scope=scope, reason=bounded_reason)
    return audit_event(
        EventKind.CONTROL_PLANE_ACTION,
        agent="control_plane",
        _global=True,
        verb=operation,
        operation=operation,
        principal="*",
        actor=actor,
        scope=scope,
        ok=result == "succeeded",
        result=result,
        reason=bounded_reason,
        detail=bounded_reason,
    )


def _halt_audit_headers(
    *,
    operation: str,
    actor: str,
    scope: str,
    result: str,
    reason: str,
    refusal_detail: str,
) -> dict[str, str]:
    from maverick.audit import AuditRefused

    try:
        written = _halt_control_audit(
            operation=operation,
            actor=actor,
            scope=scope,
            result=result,
            reason=reason,
        )
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=refusal_detail) from exc
    return {_HALT_AUDIT_HEADER: str(bool(written)).lower()}


def _halt_failure(
    *,
    operation: str,
    actor: str,
    scope: str,
    result: str,
    reason: str,
    detail: str,
    refusal_detail: str,
    cause: BaseException,
    status_code: int = 503,
) -> NoReturn:
    headers = _halt_audit_headers(
        operation=operation,
        actor=actor,
        scope=scope,
        result=result,
        reason=reason,
        refusal_detail=refusal_detail,
    )
    raise HTTPException(
        status_code=status_code,
        detail=detail,
        headers=headers,
    ) from cause


def _halt_path_is_alias(info) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _HALT_REPARSE_ATTRIBUTE
    )


def _halt_file_identity(info) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _stable_local_halt_read(path) -> tuple[bytes | None, object | None]:
    """Read bounded HALT detail from the regular file verified by its handle.

    ``None`` bytes with a stat result means the file is deliberately too large
    to disclose.  ``(None, None)`` is a stable absent file.  Aliases, hard links
    and identity-changing reads fail closed.
    """

    last_error: Exception | None = None
    for _attempt in range(3):
        try:
            before = path.lstat()
        except FileNotFoundError:
            return None, None
        except OSError as exc:
            last_error = exc
            continue
        if (
            _halt_path_is_alias(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_ino == 0
        ):
            raise HTTPException(
                status_code=503,
                detail="halt authority is unavailable",
            )
        if before.st_size > _HALT_DETAIL_MAX_BYTES:
            return None, before
        try:
            with open(path, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or _halt_file_identity(before) != _halt_file_identity(opened)
                ):
                    continue
                raw = stream.read(_HALT_DETAIL_MAX_BYTES + 1)
                after_handle = os.fstat(stream.fileno())
        except OSError as exc:
            last_error = exc
            continue
        if len(raw) > _HALT_DETAIL_MAX_BYTES:
            return None, after_handle
        try:
            after_path = path.lstat()
        except OSError as exc:
            last_error = exc
            continue
        stable = (
            not _halt_path_is_alias(after_path)
            and stat.S_ISREG(after_path.st_mode)
            and after_path.st_nlink == 1
            and _halt_file_identity(before) == _halt_file_identity(after_handle)
            and _halt_file_identity(after_handle) == _halt_file_identity(after_path)
            and before.st_size == after_handle.st_size == after_path.st_size == len(raw)
            and before.st_mtime_ns
            == after_handle.st_mtime_ns
            == after_path.st_mtime_ns
        )
        if stable:
            return raw, after_handle
    raise HTTPException(
        status_code=503,
        detail="halt authority is unavailable",
    ) from last_error


def _local_halt_details(path) -> dict:
    """Read bounded local HALT metadata without returning its raw payload."""

    raw, info = _stable_local_halt_read(path)
    if info is None:
        return {"file_present": False, "reason": None, "armed_at": None,
                "armed_by": None}

    reason = None
    armed_by = None
    if raw is not None:
        body = raw.decode("utf-8", errors="replace").strip()
        if body:
            try:
                parsed = json.loads(body)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                value = parsed.get("reason")
                reason = str(value)[:500] if value else None
                actor = parsed.get("actor") or parsed.get("source")
                armed_by = str(actor)[:256] if actor else None
            else:
                reason = body[:500]
    return {
        "file_present": True,
        "reason": reason,
        "armed_at": info.st_mtime,
        "armed_by": armed_by,
    }


@router.get("/halt")
def halt_status(request: Request) -> dict:
    """Show every workspace reader if work is stopped; keep incident detail global."""

    require_permission(request, "view")
    shared_backend = _halt_backend_or_503()

    from maverick.killswitch import Halted, _halt_file_path, check

    try:
        check(force_refresh=True, fail_closed=True)
    except Halted as exc:
        if exc.source in {"file-error", "shared-error"}:
            raise HTTPException(
                status_code=503,
                detail="halt authority is unavailable",
            ) from exc
        active = True
    else:
        active = False

    path = _halt_file_path()
    local = _local_halt_details(path)
    shared_state = None
    if shared_backend:
        try:
            shared_state = _world().active_halt()
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="halt authority is unavailable",
            ) from exc
        if shared_state is not None and not isinstance(shared_state, dict):
            raise HTTPException(
                status_code=503,
                detail="halt authority is unavailable",
            )
        active = bool(active or shared_state)

    out: dict = {
        "active": active,
        "scope": "cluster" if shared_backend else "local",
    }
    if shared_backend:
        out["cluster_halt"] = bool(shared_state)

    if has_global_permission(request, "audit"):
        if shared_state:
            # An old local file can survive a prior partial clear.  While the
            # shared halt is active, its row is the cluster authority and must
            # own the incident attribution instead of being shadowed by stale
            # local metadata.
            shared_reason = shared_state.get("reason")
            shared_actor = shared_state.get("armed_by")
            reason = str(shared_reason)[:500] if shared_reason else None
            armed_at = shared_state.get("armed_at")
            armed_by = str(shared_actor)[:256] if shared_actor else None
        else:
            reason = local["reason"]
            armed_at = local["armed_at"]
            armed_by = local["armed_by"]
        out.update({
            "file_present": local["file_present"],
            "reason": reason,
            "armed_at": armed_at,
            "armed_by": armed_by,
        })
    if has_global_permission(request, "admin"):
        out["file"] = str(path)
    return out


@router.post("/halt", status_code=204)
def halt_set(request: Request, payload: HaltIn, response: Response) -> None:
    """Arm the verified local HALT authority and any configured shared one.

    The mutation always attempts a deployment-global control-plane audit row.
    A configured audit refusal is returned after reporting the observed HALT
    state; an ordinary fail-soft audit outage is exposed by
    ``X-Second-Shift-Audit-Written: false``.
    """
    shared_backend = _require_halt_permission(request)
    from maverick.killswitch import _halt_file_path

    actor = _request_actor(request)
    scope = "cluster" if shared_backend else "local"
    reason = _bounded_halt_reason(
        payload.reason,
        fallback="manual via dashboard",
    )
    p = _halt_file_path()
    try:
        _publish_local_halt(
            p,
            actor=actor,
            reason=reason,
            scope=scope,
            source="dashboard",
        )
    except Exception as exc:
        _halt_failure(
            operation="halt",
            actor=actor,
            scope=scope,
            result="failed",
            reason=reason,
            detail="halt authority is unavailable",
            refusal_detail=(
                "halt was not confirmed and the required control-plane audit "
                "was refused"
            ),
            cause=exc,
        )
    # Also arm the cluster-wide halt in the shared store so the stop propagates
    # to every replica (the file only halts this one). Only on a shared backend
    # (Postgres): on single-host SQLite the file halt is the whole mechanism and
    # the killswitch doesn't consult the shared row. Best-effort -- a shared-store
    # error keeps the local stop armed but MUST be reported: a 204 would tell
    # the operator that every replica stopped when propagation actually failed.
    if shared_backend:
        try:
            _world().arm_halt(reason, source="dashboard", armed_by=actor)
        except Exception as exc:
            log.warning("cluster-wide halt arm failed (local file halt still set)", exc_info=True)
            _halt_failure(
                operation="halt",
                actor=actor,
                scope=scope,
                result="partial",
                reason=reason,
                detail=(
                    "local halt is armed, but cluster-wide propagation failed; "
                    "other replicas may still be running"
                ),
                refusal_detail=(
                    "local halt is armed, cluster propagation failed, and the "
                    "required control-plane audit was refused"
                ),
                cause=exc,
            )
    headers = _halt_audit_headers(
        operation="halt",
        actor=actor,
        scope=scope,
        result="succeeded",
        reason=reason,
        refusal_detail=(
            "halt is armed, but the required control-plane audit was refused"
        ),
    )
    response.headers.update(headers)


@router.delete("/halt", status_code=204)
def halt_clear(  # noqa: C901 - explicit fail-safe cross-authority transaction
    request: Request,
    response: Response,
) -> None:
    """Clear the verified local HALT authority and any configured shared one."""
    shared = _require_halt_permission(request)
    step_up.require_recent_mfa(request, "clear_emergency_stop")
    from maverick import killswitch
    from maverick.file_lock import cross_process_lock, require_private_directory
    from maverick.killswitch import (
        _begin_clear_transition_hold,
        _end_clear_transition_hold,
        _halt_authority_lock_path,
        _halt_file_generation,
        _halt_file_path,
    )

    actor = _request_actor(request)
    scope = "cluster" if shared else "local"
    reason = "operator requested halt clear"
    p = _halt_file_path()
    try:
        require_private_directory(p.parent)
        local_before = _halt_file_generation(p)
        process_before = killswitch._in_process_halt_generation()
    except Exception as exc:
        _halt_failure(
            operation="clear-halt",
            actor=actor,
            scope=scope,
            result="failed",
            reason=reason,
            detail="halt clear was not attempted because its local authority is unavailable",
            refusal_detail=(
                "halt clear was not attempted and the required control-plane "
                "audit was refused"
            ),
            cause=exc,
        )

    world = None
    shared_before = None
    shared_generation = None
    if shared:
        # Resolve and read the shared authority while the durable local stop is
        # still present.  A connection/read failure must not begin a clear.
        try:
            world = _world()
            shared_before = world.active_halt()
            if shared_before is not None and not isinstance(shared_before, dict):
                raise RuntimeError("invalid shared halt state")
            if shared_before is not None:
                shared_generation = shared_before.get("generation")
                if not isinstance(shared_generation, str):
                    raise RuntimeError("shared halt generation is unavailable")
        except Exception as exc:
            _halt_failure(
                operation="clear-halt",
                actor=actor,
                scope=scope,
                result="failed",
                reason=reason,
                detail=(
                    "halt clear was not attempted because the cluster halt "
                    "authority is unavailable"
                ),
                refusal_detail=(
                    "halt clear was not attempted and the required "
                    "control-plane audit was refused"
                ),
                cause=exc,
            )
    def _delete_exact_local_generation() -> None:
        """Remove only the local generation observed before this clear."""

        with cross_process_lock(_halt_authority_lock_path(p), strict=True):
            if _halt_file_generation(p) != local_before:
                raise _ConcurrentHalt("newer local HALT generation observed")
            if local_before is not None:
                p.unlink()

    if not shared:
        # A local clear can bind the exact file deletion and in-process CAS in
        # one strict control barrier.  An overlapping arm changes either token
        # and is retained.
        try:
            killswitch.clear(
                durable_clear=_delete_exact_local_generation,
                expected_in_process_generation=process_before,
            )
        except (killswitch.HaltGenerationChanged, _ConcurrentHalt) as exc:
            _halt_failure(
                operation="clear-halt",
                actor=actor,
                scope=scope,
                result="superseded",
                reason=reason,
                detail=(
                    "halt clear was not applied because a newer local halt is armed"
                ),
                refusal_detail=(
                    "a newer local halt remains armed and the required "
                    "control-plane audit was refused"
                ),
                cause=exc,
                status_code=409,
            )
        except Exception as exc:
            _halt_failure(
                operation="clear-halt",
                actor=actor,
                scope=scope,
                result="failed",
                reason=reason,
                detail="halt remains armed because the local clear barrier failed",
                refusal_detail=(
                    "halt remains armed and the required control-plane audit was refused"
                ),
                cause=exc,
            )
    else:
        # The shared transaction locks the exact database generation before it
        # invokes the local unlink.  The temporary process hold covers this
        # server until commit/rollback and is released only by its own token.
        try:
            transition_hold = _begin_clear_transition_hold()
        except Exception as exc:
            _halt_failure(
                operation="clear-halt",
                actor=actor,
                scope=scope,
                result="failed",
                reason=reason,
                detail="halt remains armed because its clear barrier is unavailable",
                refusal_detail=(
                    "halt remains armed and the required control-plane audit was refused"
                ),
                cause=exc,
            )

        try:
            assert world is not None
            if shared_before is None:
                _delete_exact_local_generation()
            else:
                removed = world.disarm_halt(
                    expected_generation=shared_generation,
                    durable_clear=_delete_exact_local_generation,
                )
                if not removed:
                    current = world.active_halt()
                    if current is not None and not isinstance(current, dict):
                        raise RuntimeError("invalid shared halt state")
                    current_generation = (
                        current.get("generation") if current is not None else None
                    )
                    if current is not None and not isinstance(
                        current_generation, str,
                    ):
                        raise RuntimeError("shared halt generation is unavailable")
                    if current_generation != shared_generation:
                        raise _ConcurrentHalt(
                            "newer shared HALT generation observed"
                        )
                    raise RuntimeError("shared halt compare-and-delete was refused")

            shared_after = world.active_halt()
            if shared_after is not None and not isinstance(shared_after, dict):
                raise RuntimeError("invalid shared halt state")
            if shared_after is not None:
                after_generation = shared_after.get("generation")
                if not isinstance(after_generation, str):
                    raise RuntimeError("shared halt generation is unavailable")
                if shared_before is None or after_generation != shared_generation:
                    raise _ConcurrentHalt("newer shared HALT generation observed")
                raise RuntimeError("shared halt remained active after clear")

            if _halt_file_generation(p) is not None:
                raise _ConcurrentHalt("newer local HALT generation observed")
            killswitch.clear(
                expected_in_process_generation=process_before,
            )
            _end_clear_transition_hold(transition_hold)
        except (killswitch.HaltGenerationChanged, _ConcurrentHalt) as exc:
            try:
                compensation = _ensure_local_halt_fail_safe(
                    p,
                    actor=actor,
                    reason=(
                        "newer halt superseded an in-flight clear; "
                        "local fail-safe retained"
                    ),
                )
            except Exception as compensation_exc:
                log.critical(
                    "local HALT compensation failed after concurrent halt",
                    exc_info=True,
                )
                detail = (
                    "a newer halt remains armed, but its local fail-safe could "
                    "not be confirmed; verify this replica immediately"
                )
                refusal_detail = (
                    "a newer halt remains armed, local compensation is unconfirmed, "
                    "and the required control-plane audit was refused"
                )
                cause = compensation_exc
            else:
                try:
                    _end_clear_transition_hold(transition_hold)
                except Exception:
                    log.critical(
                        "HALT clear transition hold could not be released safely",
                        exc_info=True,
                    )
                detail = (
                    "halt clear was superseded by a newer cluster halt; the local "
                    f"fail-safe was {compensation}"
                )
                refusal_detail = (
                    "a newer cluster halt and its local fail-safe remain armed, "
                    "and the required control-plane audit was refused"
                )
                cause = exc
            _halt_failure(
                operation="clear-halt",
                actor=actor,
                scope=scope,
                result="superseded",
                reason=reason,
                detail=detail,
                refusal_detail=refusal_detail,
                cause=cause,
                status_code=409,
            )
        except Exception as exc:
            # A transaction/commit failure can have an indeterminate external
            # result.  Restore a durable local stop before releasing this
            # process's temporary hold.
            log.warning(
                "cluster-wide halt clear could not be confirmed",
                exc_info=(type(exc), exc, exc.__traceback__),
            )
            try:
                compensation = _ensure_local_halt_fail_safe(
                    p,
                    actor=actor,
                    reason=(
                        "cluster halt clear could not be confirmed; "
                        "local fail-safe re-armed"
                    ),
                )
            except Exception as compensation_exc:
                log.critical(
                    "local HALT compensation failed after cluster clear uncertainty",
                    exc_info=True,
                )
                detail = (
                    "cluster halt clear is indeterminate and the local fail-safe "
                    "could not be re-armed; verify every replica immediately"
                )
                refusal_detail = (
                    "halt clear and local compensation are indeterminate, and the "
                    "required control-plane audit was refused"
                )
                cause = compensation_exc
            else:
                try:
                    _end_clear_transition_hold(transition_hold)
                except Exception:
                    log.critical(
                        "HALT clear transition hold could not be released safely",
                        exc_info=True,
                    )
                detail = (
                    "cluster halt clear is indeterminate; the local fail-safe was "
                    f"{compensation}, but other replicas may be running"
                )
                refusal_detail = (
                    "the local fail-safe was restored after an indeterminate "
                    "cluster clear, and the required control-plane audit was refused"
                )
                cause = exc
            _halt_failure(
                operation="clear-halt",
                actor=actor,
                scope=scope,
                result="partial",
                reason=reason,
                detail=detail,
                refusal_detail=refusal_detail,
                cause=cause,
            )

    # Never claim success while a newer local generation is visible.  This is
    # also the final guard for local-only clears.
    try:
        local_after = _halt_file_generation(p)
    except Exception as exc:
        _halt_failure(
            operation="clear-halt",
            actor=actor,
            scope=scope,
            result="indeterminate",
            reason=reason,
            detail="halt clear completed, but the local authority cannot be verified",
            refusal_detail=(
                "local halt state is unverified and the required control-plane "
                "audit was refused"
            ),
            cause=exc,
        )
    if local_after is not None:
        _halt_failure(
            operation="clear-halt",
            actor=actor,
            scope=scope,
            result="superseded",
            reason=reason,
            detail="halt clear was superseded by a newer local halt",
            refusal_detail=(
                "a newer local halt remains armed and the required control-plane "
                "audit was refused"
            ),
            cause=_ConcurrentHalt("newer local HALT generation observed"),
            status_code=409,
        )
    headers = _halt_audit_headers(
        operation="clear-halt",
        actor=actor,
        scope=scope,
        result="succeeded",
        reason=reason,
        refusal_detail=(
            "halt was cleared, but the required control-plane audit was refused"
        ),
    )
    response.headers.update(headers)


@router.post("/trust/agents/{agent_id}/revoke")
async def trust_agent_revoke(request: Request, agent_id: str, payload: TrustRevokeIn) -> dict:
    """Revoke (or restore) a managed external agent (admin). Entries defined in
    the operator's config file can't be flipped here -- register the same id
    from the app first to take it under management."""
    from .trust_page_api import set_agent_blocked

    await run_in_threadpool(set_agent_blocked, request, agent_id, payload.revoked)
    return {"ok": True, "id": agent_id, "revoked": payload.revoked}


@router.get("/external-agents")
async def external_agents_list(request: Request) -> dict:
    """The bring-your-own-agent roster: platform provenance, ownership,
    ceilings, lifecycle, reported spend, and which credential surfaces each
    agent holds (never token values)."""
    require_page_permission(request, "/external-agents")
    from maverick import external_agents as xa

    return {"enabled": xa.enabled(), "status": xa.status(), "agents": xa.roster()}


@router.post("/external-agents", status_code=201)
async def external_agent_enroll(request: Request, payload: ExternalAgentIn) -> dict:
    """Enroll an agent built on another platform (admin): trust entry +
    fleet-memory roster + platform metadata in one call."""
    require_permission(request, "admin")
    from maverick import external_agents as xa

    try:
        out = xa.enroll(
            payload.id,
            payload.platform,
            description=payload.description,
            owner=payload.owner,
            department=payload.department,
            allow_tools=payload.allow_tools,
            deny_tools=payload.deny_tools,
            max_risk=payload.max_risk,
            max_dollars=payload.max_dollars,
            max_wall_seconds=payload.max_wall_seconds,
            data_scopes=payload.data_scopes,
            expires_days=payload.expires_days,
            budget_period=payload.budget_period,
            enrolled_by=caller_principal(request) or "admin",
            external_ref=payload.external_ref,
        )
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return out


@router.post("/external-agents/{agent_id}/release")
async def external_agent_release(request: Request, agent_id: str) -> dict:
    """Lift an auto-containment and clear the denial window (admin)."""
    require_permission(request, "admin")
    from maverick import external_agents as xa
    from maverick.revocation import ProtectedRevocationError, shared

    try:
        released = shared().run_if_unprotected(
            f"agent:{agent_id}",
            lambda: xa.release(
                agent_id,
                released_by=caller_principal(request) or "admin",
            ),
        )
    except ProtectedRevocationError as exc:
        raise HTTPException(
            status_code=409,
            detail="agent is security-contained; use the control-plane release",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="containment authority is unavailable; gateway release refused",
        ) from exc

    if not released:
        raise HTTPException(status_code=404, detail=f"agent {agent_id!r} is not enrolled")
    return {"ok": True, "id": agent_id}


@router.post("/external-agents/{agent_id}/reset-budget")
async def external_agent_reset_budget(request: Request, agent_id: str) -> dict:
    """Zero the active budget meter and clear the over-budget flag (admin).
    Lifetime totals are preserved — this changes what counts against the
    cap, never what was historically reported."""
    require_permission(request, "admin")
    from maverick import external_agents as xa

    if not xa.reset_budget(agent_id, reset_by=caller_principal(request) or "admin"):
        raise HTTPException(status_code=404, detail=f"agent {agent_id!r} is not enrolled")
    return {"ok": True, "id": agent_id}


@router.get("/external-agents/{agent_id}")
async def external_agent_detail(request: Request, agent_id: str, response: Response) -> dict:
    """One enrolled agent: roster row + its Operating Record footprint
    (spend, recent episodes)."""
    from .external_agent_detail_service import detail_for

    response.headers["Cache-Control"] = "private, no-store"
    return await run_in_threadpool(detail_for, request, agent_id)


@router.post("/external-agents/{agent_id}/credentials")
async def external_agent_mint(
    request: Request, agent_id: str, payload: ExternalCredentialIn
) -> dict:
    """Mint or rotate one per-surface bearer (admin). The token appears in
    THIS response only — it is stored for verification, never for reading.
    With ``[external_agents] mint_approval`` on, the first call parks a
    step-up approval and answers 409 with its id; re-post with
    ``approval_id`` once a decision-maker approves."""
    require_permission(request, "admin")
    from maverick import external_agents as xa

    from .approval_authority import require_approval_authority

    try:
        mint_authority = require_approval_authority(
            request,
            action="external_agents.credential_mint",
            resource=f"{agent_id}:{payload.surface}",
        )
        token = xa.mint_token(
            agent_id,
            payload.surface,
            mint_approval_id=payload.approval_id,
            mint_authority=mint_authority,
        )
    except xa.MintApprovalPending as e:
        return JSONResponse(
            status_code=409,
            content={"detail": str(e), "status": "approval_required", "approval_id": e.approval_id},
        )
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"ok": True, "id": agent_id, "surface": payload.surface, "token": token}


@router.delete("/external-agents/{agent_id}", status_code=204)
async def external_agent_unenroll(request: Request, agent_id: str) -> None:
    """Unenroll (admin): removes the managed trust entry + metadata. The
    fleet-memory roster keeps its history — provenance is never rewritten.
    Prefer revoking (POST /trust/agents/{id}/revoke) to keep the entry."""
    require_permission(request, "admin")
    from maverick import external_agents as xa
    from maverick.agent_trust import ChangeNotRecorded, RevokedAgentRemovalRefused
    from maverick.audit import AuditRefused

    from .trust_page_api import _UNRECORDED, _UNSAVED, _actor

    try:
        removed = xa.unenroll(agent_id, actor=_actor(request))
    except RevokedAgentRemovalRefused as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except (AuditRefused, ChangeNotRecorded) as e:
        raise HTTPException(status_code=503, detail=_UNRECORDED) from e
    except OSError as e:
        raise HTTPException(status_code=503, detail=_UNSAVED) from e
    if not removed:
        raise HTTPException(status_code=404, detail=f"agent {agent_id!r} is not enrolled")
