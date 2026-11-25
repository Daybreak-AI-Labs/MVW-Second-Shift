"""Hand-over from a person's own recorder, and the key that allows it.

Two groups of routes.

For the signed-in person (``/api/v1/ekko/device-key``): create, look at or
remove the key for a device they have enrolled. Access matches the Ekko
session controls: ``operate``, the same-origin guard, and a store scoped to
the signed-in person and workspace. The key is shown once, on creation.

For the recorder on that person's computer (``/api/v1/external/ekko/``): it
presents the device key and nothing else, and can do exactly two things for
its own device. ``GET instructions`` says whether to observe. ``POST handover``
delivers a small batch of activities for the running session. A browser
session is not a credential here, and a device key is not a credential
anywhere else: the prefix is one of the self-authenticating ones, so these
routes never consult the dashboard sign-in, and every other route refuses a
bearer it does not know.

Every hand-over is checked again as an imported activity file is: Ekko on, the
enrollment current and inside the administrator's ceiling, the named session
running, each activity allowed by the enrolled policy, the emergency stop, and
the required "start authorized" audit row whenever the recorder attaches to a
session. Anything not allowed is dropped and counted, never stored. The store's
own exclusive recorder lease and running-state check still apply underneath.

What this module does not do: it never starts, pauses, resumes or stops a
session (only the person does, on the page); it returns no recorded data, no
suggestions and no plans; it accepts application switches only, whatever the
installation's capture level; and it repeats nothing a recorder sent in any
reply, log line or audit row.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from maverick import ekko_device_keys as keys
from maverick.work_discovery import CapturePolicy, ObservedActivity, SessionState, WorkEvent, WorkSession
from maverick.work_discovery_store import (
    MAX_EVENTS_PER_SESSION,
    CollectorLeaseError,
    EnrollmentRequired,
    EventConflictError,
    SessionStateError,
    WorkDiscoveryStore,
    WorkDiscoveryStoreError,
)

from . import auth
from . import ekko_routes as ekko

log = logging.getLogger(__name__)
router = APIRouter(tags=["ekko"])

#: A hand-over request body may be at most this large.
MAX_BODY_BYTES = 16 * 1024
#: A hand-over may carry at most this many activities.
MAX_BATCH_ACTIVITIES = 50
#: How far behind the server's clock a kept activity time may be.
MAX_ACTIVITY_AGE_SECONDS = 600.0
#: Requests a minute for one device key, and refused keys a minute for one address.
_RATE_LIMITS = {"instructions": 120, "handover": 60, "refused": 30}
_RATE_BUCKET_CAP = 10_000
_rate_times: dict[tuple[str, str], deque[float]] = {}
_rate_lock = threading.Lock()

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,63}$")
_ACCOUNT_RE = re.compile(r"^[0-9a-f]{64}$")
_BATCH_FIELDS = frozenset({"session_id", "batch_id", "account", "activities"})
_ACTIVITY_FIELDS = frozenset({"app", "action", "object_type", "duration_seconds", "occurred_at"})


def _now() -> float:
    """The server's clock, in one place so a test can move it."""
    return time.time()


def _refusal(status: int, code: str, message: str, **headers: str) -> HTTPException:
    """A fixed, plain answer. Nothing a caller sent is ever part of it."""
    return HTTPException(status_code=status, detail={"code": code, "message": message}, headers=headers or None)


def _invalid_key() -> HTTPException:
    # One answer for an unknown, replaced or ended key.
    return _refusal(401, "invalid_device_key", "This recorder key is not valid. Create a new one on the Ekko page.")


def _not_accepted(what: str) -> HTTPException:
    return _refusal(503, "not_accepted", f"{what} could not be checked. Nothing was accepted.")


def _too_many() -> HTTPException:
    return _refusal(429, "slow_down", "Too many requests. Wait a minute, then try again.", **{"Retry-After": "60"})


def _over_limit(key: str, action: str, *, count: bool = True) -> bool:
    """Whether ``key`` has used up this minute's allowance for ``action``.

    A request inside the allowance is counted against it, unless ``count`` is
    false (a look before deciding whether the request counts).
    """
    now = time.monotonic()
    bucket = (action, key)
    from .worker_coordination import active_root, rate_allowed

    if (root := active_root()) is not None:
        return not rate_allowed(root, "ekko", bucket, _RATE_LIMITS[action], _RATE_BUCKET_CAP, count_hit=count)
    with _rate_lock:
        if bucket not in _rate_times and len(_rate_times) >= _RATE_BUCKET_CAP:
            for candidate, window in tuple(_rate_times.items()):
                while window and now - window[0] >= 60:
                    window.popleft()
                if not window:
                    _rate_times.pop(candidate, None)
            if len(_rate_times) >= _RATE_BUCKET_CAP:
                return True
        window = _rate_times.setdefault(bucket, deque())
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= _RATE_LIMITS[action]:
            return True
        if count:
            window.append(now)
        return False


# --- the signed-in person's key ------------------------------------------------

def _workspace() -> str | None:
    from maverick.paths import current_tenant_id

    return current_tenant_id()


def _heard(key: keys.DeviceKey) -> None:
    """Remember that the recorder called. Never a reason to refuse it."""
    try:
        keys.note_heard(key, now=_now())
    except Exception as exc:
        log.debug("Ekko hand-over: last-heard time not written (%s)", type(exc).__name__)


def _drop(key: keys.DeviceKey) -> None:
    """Remove the record of a key that has ended. It is refused either way."""
    try:
        keys.forget(key)
    except Exception as exc:
        log.warning("Ekko hand-over: an ended recorder key was not removed (%s)", type(exc).__name__)


def _ended(key: keys.DeviceKey, enrollment) -> bool:
    """A key ends with the enrollment it was created under: withdrawn,
    expired, replaced by a new enrollment, or the device forgotten."""
    return enrollment is None or not enrollment.active or keys.enrollment_fingerprint(enrollment) != key.enrollment


def _live_key(request: Request, device_id: str) -> keys.DeviceKey | None:
    """This person's key for the device, or ``None``. A key whose enrollment
    has ended is removed here, so its record does not outlive the consent."""
    device = ekko._device_id(device_id)
    try:
        key = keys.for_device(ekko._owner(request), device, tenant=_workspace())
    except keys.DeviceKeyError as exc:
        raise HTTPException(503, "The recorder key could not be read, so nothing is accepted from the recorder. "
                                 "Remove the key and create a new one.") from exc
    if key is None:
        return None
    store = ekko._store(request, device)
    try:
        enrollment = store.get_enrollment() if store.has_storage() else None
    except EnrollmentRequired:
        enrollment = None
    except WorkDiscoveryStoreError:
        return None  # not provably current: shown as no key, and refused on hand-over
    if _ended(key, enrollment):
        _drop(key)
        return None
    return key


def recorder_status(request: Request, device_id: str) -> dict:
    """What the page shows about the recorder: never the key or its hash."""
    from maverick.config import get_ekko

    key = _live_key(request, device_id)
    heard_within = max(90.0, 6.0 * float(get_ekko()["poll_interval_seconds"]))
    heard_at = key.heard_at if key is not None else None
    return {
        "device_id": ekko._device_id(device_id),
        "has_key": key is not None,
        "created_at": key.created_at if key is not None else None,
        "last_heard_at": heard_at,
        "heard_recently": heard_at is not None and _now() - heard_at <= heard_within,
    }


@router.get("/api/v1/ekko/device-key")
def device_key_status(
    request: Request,
    device_id: str = Query(ekko._DEFAULT_DEVICE, min_length=1, max_length=64),
) -> dict:
    """Whether this device has a recorder key and when the recorder last called."""
    auth.require_permission(request, "operate")
    return recorder_status(request, device_id)


@router.post("/api/v1/ekko/device-key", status_code=201)
def create_device_key(request: Request, payload: ekko.DeviceIn) -> JSONResponse:
    """Create, or replace, the recorder key for a device this person enrolled.

    Returned once and never again. An earlier key for the device stops working
    in the same step. Refused unless the audit record can take the entry.
    """
    from maverick.audit import EventKind

    from .ekko_ops_api import _access

    ekko._require_same_origin(request)
    _access(request)
    ekko._require_enabled_policy()
    store = ekko._store(request, payload.device_id)
    ekko._validated_enrolled_policy(store)
    enrollment = ekko._active_enrollment(store)
    ekko._audit(EventKind.EKKO_CONSENT_CHANGED, required=True, state="device_key_authorized")
    try:
        key, record = keys.create(
            ekko._owner(request), ekko._device_id(payload.device_id), tenant=_workspace(),
            enrollment=keys.enrollment_fingerprint(enrollment), now=_now(),
        )
    except Exception as exc:
        log.warning("Ekko: a recorder key could not be saved (%s)", type(exc).__name__)
        raise HTTPException(503, "The recorder key could not be created. Nothing changed; try again.") from exc
    ekko._audit(EventKind.EKKO_CONSENT_CHANGED, state="device_key_created")
    body = {"device_key": key, "shown_once": True, "recorder": {
        "device_id": record.device_id, "has_key": True, "created_at": record.created_at,
        "last_heard_at": None, "heard_recently": False}}
    return JSONResponse(body, status_code=201, headers={"Cache-Control": "no-store"})


@router.delete("/api/v1/ekko/device-key")
def remove_device_key(
    request: Request,
    device_id: str = Query(ekko._DEFAULT_DEVICE, min_length=1, max_length=64),
) -> dict:
    """Remove the recorder key: the recorder is refused from its next call."""
    from maverick.audit import EventKind

    ekko._require_same_origin(request)
    auth.require_permission(request, "operate")
    removed = keys.revoke(ekko._owner(request), ekko._device_id(device_id), tenant=_workspace())
    if removed:
        ekko._audit(EventKind.EKKO_CONSENT_CHANGED, state="device_key_revoked")
    return {"removed": removed}


# --- the recorder ----------------------------------------------------------------

@dataclass(frozen=True)
class _Device:
    """The device a presented key belongs to, with its own store."""

    key: keys.DeviceKey
    store: WorkDiscoveryStore
    collector_id: str
    policy: CapturePolicy


def _open_store(key: keys.DeviceKey) -> WorkDiscoveryStore:
    return WorkDiscoveryStore(key.owner, key.device_id, tenant=key.tenant, clock=_now)


def _workspace_unchanged(key: keys.DeviceKey) -> bool:
    """Whether the key's workspace is still where its person works.

    A signed-in person works in the installation's workspace, or in their own
    when per-person workspaces are on. A key recorded under anything else
    would write where its person can no longer see or stop it, so it is
    refused.
    """
    from maverick.paths import current_tenant_id, tenant_by_user_enabled

    current = current_tenant_id()
    if current is not None or key.tenant is None:
        return key.tenant == current
    return tenant_by_user_enabled() and key.tenant == f"api:{key.owner}"


@contextmanager
def _in_workspace(key: keys.DeviceKey) -> Iterator[None]:
    """Read settings, the emergency stop and the audit record as the key's workspace."""
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant

    if key.tenant == current_tenant_id():
        yield
        return
    token = set_tenant(key.tenant)
    try:
        yield
    finally:
        reset_tenant(token)


def _known_key(request: Request) -> keys.DeviceKey:
    """The record of the key this request presents, or a refusal.

    The key is the identity: no cookie, no sign-in and no other header is
    looked at. An address that keeps presenting keys that are not valid is
    turned away before the next one is looked up.
    """
    header = request.headers.get("authorization", "")
    presented = header[7:].strip() if header.startswith("Bearer ") else ""
    if not presented:
        raise _refusal(401, "missing_device_key", "A recorder key is required.")
    address = request.client.host if request.client else "unknown"
    if _over_limit(address, "refused", count=False):
        raise _too_many()
    try:
        key = keys.find(presented)
        valid = key is not None and _workspace_unchanged(key)
    except Exception as exc:
        # An unreadable record or workspace setting: refuse, never fall back.
        log.warning("Ekko hand-over: a recorder key could not be checked (%s)", type(exc).__name__)
        raise _not_accepted("The recorder key") from exc
    if not valid:
        _over_limit(address, "refused")
        raise _invalid_key()
    return key


@contextmanager
def _device(request: Request, action: str) -> Iterator[_Device]:
    """Resolve the caller to its device and current enrollment, or refuse."""
    checked = getattr(request.state, "verified_recorder_for_instructions", None) if action == "instructions" else None
    key = checked if checked is not None else _known_key(request)
    if _over_limit(key.key_id, action):
        raise _too_many()
    with _in_workspace(key):
        store = _open_store(key)
        enrollment, policy = None, None
        try:
            if store.has_storage():
                enrollment, policy = store.enrollment_and_policy()
        except EnrollmentRequired:
            enrollment = None
        except WorkDiscoveryStoreError as exc:
            raise _not_accepted("The enrollment") from exc
        if _ended(key, enrollment):
            _drop(key)
            _over_limit(request.client.host if request.client else "unknown", "refused")
            raise _invalid_key()
        if policy is None:
            raise _invalid_key()
        collector = "handover-" + hashlib.sha256(
            f"ekko:handover-collector:v1:{key.tenant or ''}:{key.owner}:{key.device_id}".encode()).hexdigest()[:40]
        yield _Device(key=key, store=store, collector_id=collector, policy=policy)


def _settings_readable() -> None:
    from maverick import config

    if config.config_source_errors(include_tenant=True):
        raise _refusal(503, "settings_unreadable", "The Ekko settings could not be read. Nothing was accepted.")


def _stopped() -> bool:
    """The emergency stop. A stop that cannot be read counts as stopped."""
    from maverick.killswitch import check

    try:
        check(force_refresh=True, fail_closed=True)
    except Exception:
        return True
    return False


def _enrolled_policy(device: _Device) -> tuple[bool, CapturePolicy, bool]:
    """``(Ekko is on, the enrolled policy, it is inside the ceiling)``, read now."""
    from maverick.config import get_ekko, validate_ekko_policy_ceiling

    settings = get_ekko()
    on = bool(settings.get("enable")) and bool(settings.get("allowed_apps"))
    policy = device.policy
    try:
        validate_ekko_policy_ceiling(policy)
    except (TypeError, ValueError):
        return on, policy, False
    return on, policy, True


def _lease_seconds(policy: CapturePolicy) -> float:
    return max(60.0, min(1200.0, float(policy.poll_interval_seconds) * 12.0))


def _renew_lease(device: _Device, session_id: str, policy: CapturePolicy) -> None:
    """Keep the recorder lease alive between hand-overs. Never takes one:
    attaching to a session happens only on a hand-over, with its audit row."""
    try:
        device.store.heartbeat_collector(session_id, device.collector_id, policy=policy,
                                         ttl_seconds=_lease_seconds(policy))
    except Exception:
        return  # no lease to renew, or not this recorder's; the next hand-over decides


def _instructions(device: _Device) -> dict:
    _settings_readable()
    on, policy, current = _enrolled_policy(device)
    now = _now()
    try:
        session, due = device.store.recorder_session(
            device.collector_id, now=now, renew_before=now - _lease_seconds(policy) / 3.0)
    except WorkDiscoveryStoreError as exc:
        raise _not_accepted("The session") from exc
    state = "none"
    if session is not None:
        state = {SessionState.RUNNING: "running", SessionState.PAUSED: "paused"}.get(session.state, "stopped")
    stopped = _stopped()
    record = on and current and state == "running" and not stopped
    if due and session is not None and on and current and not stopped and state in {"running", "paused"}:
        _renew_lease(device, session.session_id, policy)
    _heard(device.key)
    reason = ("recording" if record else "ekko_off" if not on else "enrollment_not_current" if not current
              else "emergency_stop" if stopped else f"session_{state}")
    return {
        "ekko_on": on,
        "enrollment_current": current,
        "session": {"state": state, "id": session.session_id if session is not None and state != "stopped" else None},
        "allowed_apps": sorted(policy.allowed_apps - policy.blocked_apps) if on and current else [],
        "poll_interval_seconds": float(policy.poll_interval_seconds),
        "record": record,
        "reason": reason,
        "batch_limit": MAX_BATCH_ACTIVITIES,
    }


@router.get("/api/v1/external/ekko/instructions")
def recorder_instructions(request: Request) -> JSONResponse:
    """What the recorder on this device should do now: observe, or wait."""
    from maverick.config import single_read
    from maverick.tenant.kms import dek_cache_policy_scope

    with single_read(fresh=True), dek_cache_policy_scope(), _device(request, "instructions") as device:
        return JSONResponse(_instructions(device), headers={"Cache-Control": "no-store"})


@dataclass(frozen=True)
class _Batch:
    session_id: str
    batch_id: str
    account: str
    activities: tuple[tuple[ObservedActivity, float], ...]


def _no_constants(_name: str) -> float:
    raise ValueError("not a number")


def _parse_activity(item: object) -> tuple[ObservedActivity, float]:
    """One activity and the time the recorder says it happened.

    The accepted fields are listed, exactly as ``ObservedActivity`` lists its
    own, so a recorder cannot carry a window title, an address or a file name
    in a field the server would otherwise ignore.
    """
    if (not isinstance(item, dict) or not set(item) <= _ACTIVITY_FIELDS
            or not {"app", "action", "occurred_at"} <= set(item)):
        raise ValueError("activity fields")
    for name in ("app", "action", "object_type"):
        if name in item and (not isinstance(item[name], str) or len(item[name]) > 32):
            raise ValueError("activity text")
    for name in ("duration_seconds", "occurred_at"):
        value = item.get(name, 0.0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("activity number")
    observed = ObservedActivity.from_mapping({name: item[name] for name in item if name != "occurred_at"})
    return observed, float(item["occurred_at"])


def _parse_batch(raw: bytes) -> _Batch:
    """Read a hand-over body strictly. A refusal says only that it was not
    understood: a validation error of the usual kind repeats the rejected value."""
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_no_constants)
        if not isinstance(value, dict) or set(value) != _BATCH_FIELDS:
            raise ValueError("batch fields")
        session_id, batch_id, account, items = (value[name] for name in ("session_id", "batch_id", "account", "activities"))
        if (not isinstance(session_id, str) or not _ID_RE.fullmatch(session_id)
                or not isinstance(batch_id, str) or not _ID_RE.fullmatch(batch_id)
                or not isinstance(account, str) or not _ACCOUNT_RE.fullmatch(account)
                or not isinstance(items, list) or not items):
            raise ValueError("batch values")
        if len(items) > MAX_BATCH_ACTIVITIES:
            raise _refusal(413, "too_large", f"A hand-over may carry at most {MAX_BATCH_ACTIVITIES} activities. "
                                             "Nothing was accepted.")
        return _Batch(session_id, batch_id, account, tuple(_parse_activity(item) for item in items))
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise _refusal(422, "not_understood",
                       "The hand-over was not in the expected form. Nothing was accepted.") from exc


def kept_time(sent: float, *, now: float, session_started: float, previous: float | None) -> float:
    """The time kept for one activity.

    The recorder says when an activity happened; the server's clock decides
    what is believable. The kept time is the recorder's time, moved when
    necessary so that it is:

    * not later than ``now``, the moment the hand-over arrived;
    * not earlier than ``MAX_ACTIVITY_AGE_SECONDS`` (ten minutes) before
      ``now``;
    * not earlier than the moment the session started;
    * not earlier than the activity kept just before it in the same session
      (this last rule wins over the others, so order is never lost).

    Why: discovery counts repeats on different days and treats activities more
    than half an hour apart as unrelated, so a time is evidence. A recorder
    hands over within seconds and retries for a few minutes at most, so an
    honest time is always inside ten minutes. A wrong laptop clock, or a
    recorder that holds a key it should not have, can therefore shift a time
    by at most ten minutes and can never place an activity on another day, in
    the future, before the person pressed Start, or out of order.
    """
    kept = min(now, max(sent, now - MAX_ACTIVITY_AGE_SECONDS, session_started))
    return kept if previous is None or kept >= previous else previous


def _event_id(batch: _Batch, index: int, observed: ObservedActivity) -> str:
    """The same activity of the same batch always gets the same id, so the
    store's unique event id is what stops a retry being stored twice."""
    body = json.dumps([batch.session_id, batch.batch_id, index, observed.app, observed.action,
                       observed.object_type, observed.duration_seconds], separators=(",", ":"))
    return "ho-" + hashlib.sha256(f"ekko:handover-event:v1:{body}".encode()).hexdigest()[:48]


def _not_running() -> HTTPException:
    return _refusal(409, "session_not_running", "Recording is not running for this device. Nothing was accepted.")


def _store_refusal(exc: Exception) -> HTTPException:
    """Turn a refusal from the store into a fixed answer for the recorder."""
    from maverick.killswitch import Halted

    if isinstance(exc, SessionStateError):
        return _not_running()
    if isinstance(exc, CollectorLeaseError):
        return _refusal(409, "another_recorder", "Another recorder is already recording this device. "
                                                 "Nothing was accepted.")
    if isinstance(exc, EnrollmentRequired):
        return _refusal(409, "enrollment_not_current", "The enrollment for this device is no longer current. "
                                                       "Enroll it again on the Ekko page.")
    if isinstance(exc, Halted):
        return _refusal(409, "emergency_stop", "Everything is stopped. Nothing was accepted.")
    log.warning("Ekko hand-over: the store refused (%s)", type(exc).__name__)
    return _refusal(503, "not_accepted", "The hand-over could not be recorded. Nothing more was accepted.")


def _attach(device: _Device, session_id: str, policy: CapturePolicy) -> None:
    """Hold the device's exclusive recorder lease for this session.

    Renewing a lease this recorder already holds needs nothing more. Taking
    one is the recorder starting on a session, so it first writes the same
    required "start authorized" audit row every other recorder start writes;
    if that row cannot be written, nothing is accepted.
    """
    from maverick.audit import EventKind

    try:
        device.store.heartbeat_collector(session_id, device.collector_id, policy=policy,
                                         ttl_seconds=_lease_seconds(policy))
    except CollectorLeaseError:
        ekko._audit(EventKind.EKKO_SESSION, required=True, session_id=session_id, state="start_authorized",
                    policy_digest=policy.fingerprint(), observer="device_recorder")
        device.store.claim_collector(session_id, device.collector_id, policy=policy,
                                     ttl_seconds=_lease_seconds(policy))


def _different_account(device: _Device) -> HTTPException:
    """Refuse a hand-over from another computer account, and record that it
    happened (content-free, and not on every retry)."""
    from maverick.audit import EventKind

    try:
        if keys.refusal_due(device.key, now=_now()):
            ekko._audit(EventKind.EKKO_SESSION, state="handover_refused", reason="different_computer_account")
    except Exception as exc:
        # The refusal stands whether or not it could be recorded.
        log.warning("Ekko hand-over: a refusal could not be recorded (%s)", type(exc).__name__)
    return _refusal(403, "different_account", "This key was first used from a different computer account. "
                                              "Create a new key on the Ekko page for this computer.")


def _store_activities(device: _Device, batch: _Batch, policy: CapturePolicy, session: WorkSession) -> dict:
    """Append the allowed activities, in order. Returns content-free counts."""
    store = device.store
    last = store.list_events(session_id=session.session_id, limit=1)
    previous = last[-1].occurred_at if last else None
    sequence = session.last_sequence
    counts = {"accepted": 0, "dropped": 0, "duplicates": 0, "times_adjusted": 0}
    now = _now()
    for index, (observed, sent) in enumerate(batch.activities):
        # The recorder path carries application switches only, even where the
        # installation lets an activity file say more.
        if not policy.allows(observed) or observed.action != "switch" or observed.object_type != "none":
            counts["dropped"] += 1
            continue
        if sequence >= MAX_EVENTS_PER_SESSION:
            raise _refusal(409, "session_full", "This recording is full. Stop it and start a new one on the Ekko page.")
        kept = kept_time(sent, now=now, session_started=session.started_at, previous=previous)
        event = WorkEvent(
            event_id=_event_id(batch, index, observed), session_id=session.session_id, sequence=sequence + 1,
            occurred_at=kept, app=observed.app, action=observed.action, object_type=observed.object_type,
            duration_seconds=observed.duration_seconds,
        )
        try:
            inserted = store.append_collector_event(event, policy=policy, collector_id=device.collector_id)
        except EventConflictError:
            inserted = False  # stored by an earlier attempt at this batch
        if not inserted:
            counts["duplicates"] += 1
            continue
        sequence += 1
        previous = kept
        counts["accepted"] += 1
        if kept != sent:
            counts["times_adjusted"] += 1
    return counts


def _accept(device: _Device, batch: _Batch) -> dict:
    from maverick.file_lock import cross_process_lock

    _settings_readable()
    if keys.account_matches(device.key, batch.account) is False:
        raise _different_account(device)
    on, policy, current = _enrolled_policy(device)
    if not on:
        raise _refusal(409, "ekko_off", "Ekko is turned off. Nothing was accepted.")
    if not current:
        raise _refusal(409, "enrollment_not_current", "Your administrator changed what Ekko may notice. "
                                                      "Enroll this device again on the Ekko page.")
    if _stopped():
        raise _refusal(409, "emergency_stop", "Everything is stopped. Nothing was accepted.")
    store = device.store
    try:
        # One hand-over at a time for a device, so activities keep their order.
        with cross_process_lock(store.path.parent / "handover" / device.collector_id, strict=True):
            session = store.get_session(batch.session_id)
            if session is None or session.state != SessionState.RUNNING:
                raise _not_running()
            _attach(device, session.session_id, policy)
            if not keys.bind_account(device.key, batch.account):
                raise _different_account(device)
            counts = _store_activities(device, batch, policy, session)
    except HTTPException:
        raise
    except Exception as exc:
        raise _store_refusal(exc) from exc
    try:
        store.flush_audit_outbox(limit=100)
    except Exception:
        pass  # already durable in the store's outbox; a later call delivers it
    _heard(device.key)
    return counts


def _hand_over(request: Request, raw: bytes) -> dict:
    from maverick.tenant.kms import dek_cache_policy_scope

    with dek_cache_policy_scope(), _device(request, "handover") as device:
        if len(raw) > MAX_BODY_BYTES:
            raise _refusal(413, "too_large", "The hand-over is too large. Nothing was accepted.")
        return _accept(device, _parse_batch(raw))


@router.post("/api/v1/external/ekko/handover")
async def recorder_handover(request: Request) -> JSONResponse:
    """Accept a small batch of activities for this device's running session."""
    # The body is capped for this prefix before it reaches any route, and the
    # key is checked before a byte of it is looked at.
    raw = await request.body()
    counts = await run_in_threadpool(_hand_over, request, raw)
    return JSONResponse(counts, headers={"Cache-Control": "no-store"})


__all__ = [
    "MAX_ACTIVITY_AGE_SECONDS",
    "MAX_BATCH_ACTIVITIES",
    "MAX_BODY_BYTES",
    "kept_time",
    "recorder_status",
    "router",
]
