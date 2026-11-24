"""Queue and deliver governance incidents to a configured ServiceNow instance.

Only fixed event descriptions and opaque references leave Second Shift.
Governance calls persist their intent locally. The dashboard timer handles
network calls and reconciliation outside the queue lock.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlencode

from . import agent_watch
from .agent_watch_servicenow import _instances
from .file_lock import atomic_read_text, atomic_write_text, cross_process_lock, ensure_private_directory

log = logging.getLogger(__name__)
_SECTION = "[servicenow_incidents]"
_TIMEOUT = 8.0
_RETRY_MAX = 900
_BATCH_SIZE = 4
_MAX_RECORDS = 5000
_ID = re.compile(r"[0-9a-f]{32}")
_CORRELATION = "u_second_shift_correlation_id"
_TABLE_PATH = "/api/now/table/incident"
_FIELDS = f"sys_id,state,{_CORRELATION}"
_DRAIN_LOCK = threading.Lock()
_TITLES = {
    "blocked": "Second Shift blocked an agent action for a rule violation",
    "drift": "Second Shift detected a high-severity change in an agent",
    "missing": "Second Shift could no longer find an agent on its platform",
    "emergency": "The Second Shift emergency stop was turned on",
}
_RESOLUTIONS = {
    "blocked": "The agent was released in Second Shift.",
    "drift": "The finding was acknowledged in Second Shift.",
    "missing": "The agent was seen on its platform again.",
    "emergency": "The emergency stop was cleared in Second Shift.",
}
_RETRY_MESSAGE = "ServiceNow delivery is waiting to retry. Check the integration and its permissions."
_QUEUE_MESSAGE = "The saved ServiceNow delivery queue could not be used."
_CONFIG_MESSAGE = "Check the ServiceNow incident settings and credentials."


class IncidentError(ValueError):
    """An incomplete ServiceNow operation. Messages come from fixed text."""


@dataclass(frozen=True)
class Settings:
    origin: str
    client_id_env: str
    client_secret_env: str
    close_code: str
    resolved_state: str
    closed_state: str
    caller_id: str


@dataclass
class Incident:
    correlation: str
    origin: str
    subject: str
    key: str
    event: str
    created: float
    resolve: bool = False
    delivered: bool = False
    sys_id: str = ""
    failures: int = 0
    retry_at: float = 0.0


def _settings() -> Settings | None:
    from .config import config_source_errors, load_global_config

    section = load_global_config().get("servicenow_incidents", {})
    if not isinstance(section, dict):
        raise IncidentError(_CONFIG_MESSAGE)
    if section.get("enabled") is not True:
        return None
    if config_source_errors(include_tenant=False):
        raise IncidentError(_CONFIG_MESSAGE)
    try:
        host = _instances({"instances": [section.get("instance")]}, _SECTION)[0]
        client = agent_watch.env_name(section, "client_id_env", _SECTION)
        secret = agent_watch.env_name(section, "client_secret_env", _SECTION)
    except agent_watch.WatchError as exc:
        raise IncidentError(_CONFIG_MESSAGE) from exc
    close_code = section.get("close_code")
    if not isinstance(close_code, str) or not 0 < len(close_code.strip()) <= 80 or not close_code.isprintable():
        raise IncidentError("Set the incident resolution code to a choice from your ServiceNow instance.")
    resolved, closed = section.get("resolved_state", "6"), section.get("closed_state", "7")
    if (not all(isinstance(choice, str) and re.fullmatch(r"-?[0-9]{1,6}", choice) for choice in (resolved, closed))
            or resolved == closed):
        raise IncidentError("Set distinct ServiceNow values for the Resolved and Closed incident states.")
    caller = section.get("caller_id", "")
    if not isinstance(caller, str) or (caller and not _ID.fullmatch(caller)):
        raise IncidentError("Use the ServiceNow record ID of the integration caller.")
    return Settings("https://" + host, client, secret, close_code.strip(), resolved, closed, caller)


def _now() -> float:
    return time.time()


def _path() -> Path:
    from .paths import data_dir

    return data_dir("servicenow_incidents.json", tenant=None)


def _read(path: Path) -> list[Incident]:
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            raise IncidentError(_QUEUE_MESSAGE)
        raw = json.loads(atomic_read_text(path))
    except FileNotFoundError:
        return []
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("records"), list):
        raise IncidentError(_QUEUE_MESSAGE)
    rows = [Incident(**entry) for entry in raw["records"]]
    correlations = {row.correlation for row in rows}
    if len(rows) > _MAX_RECORDS or len(rows) != len(correlations) or any(
        row.event not in _TITLES or not _ID.fullmatch(row.correlation)
        or (row.sys_id and not _ID.fullmatch(row.sys_id)) or not _ID.fullmatch(row.subject)
        for row in rows
    ):
        raise IncidentError(_QUEUE_MESSAGE)
    return rows


@contextmanager
def _editing() -> Iterator[list[Incident]]:
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        rows = _read(path)
        before = [asdict(row) for row in rows]
        yield rows
        after = [asdict(row) for row in rows]
        if before != after:
            atomic_write_text(path, json.dumps({"version": 1, "records": after}, separators=(",", ":")), mode=0o600)


def enqueue(event: str, agent_id: str = "", *, cause: str = "", resolve: bool = False) -> None:
    """Coalesce a governance event into a durable incident intent."""
    from . import practice
    from .paths import current_tenant_id_strict

    settings = _settings()
    if settings is None or practice.active() or event not in _TITLES or (event != "emergency" and not agent_id):
        return
    tenant = "" if event == "emergency" else current_tenant_id_strict()
    subject = hashlib.sha256(json.dumps([tenant, agent_id], separators=(",", ":")).encode()).hexdigest()[:32]
    key = hashlib.sha256(json.dumps([subject, event, cause], separators=(",", ":")).encode()).hexdigest()
    with _editing() as rows:
        active = [row for row in rows if row.origin == settings.origin and row.subject == subject
                  and row.event == event and (row.key == key or (resolve and not cause)) and not row.resolve]
        if resolve:
            for row in active:
                row.resolve = True
                row.delivered = False
                row.retry_at = 0
            return
        if active:
            return
        if len(rows) >= _MAX_RECORDS:
            retired = next((row for row in rows if row.resolve and row.delivered), None)
            if retired is None:
                raise IncidentError("The ServiceNow delivery queue is full.")
            rows.remove(retired)
        rows.append(Incident(uuid.uuid4().hex, settings.origin, subject, key, event, _now()))


def status() -> dict | None:
    """Plain delivery health for the alert status view."""
    try:
        settings = _settings()
        if settings is None:
            return None
        rows = _read(_path())
        pending = [row for row in rows if not row.delivered]
        retrying = sum(bool(row.failures) for row in pending)
        problem = _RETRY_MESSAGE if retrying else ""
        if any(row.origin != settings.origin for row in pending):
            problem = "Some incidents are still queued for the former ServiceNow instance."
        for name in ("client_id_env", "client_secret_env"):
            agent_watch.secret_named(getattr(settings, name), f"{_SECTION} {name}")
        return {"ready": not problem, "problem": problem, "pending": len(pending), "retrying": retrying}
    except IncidentError as exc:
        problem = str(exc)
    except agent_watch.WatchError:
        problem = _CONFIG_MESSAGE
    except (OSError, TypeError, ValueError, RecursionError):
        problem = _QUEUE_MESSAGE
    return {"ready": False, "problem": problem, "pending": None, "retrying": None}


def _token(settings: Settings) -> str:
    # Register an OAuth application user. Give it incident create/read/write
    # access, such as the documented sn_incident_write role with matching ACLs.
    # https://www.servicenow.com/docs/r/platform-security/authentication/configure-an-oauth-client-credential-grant.html
    # https://www.servicenow.com/docs/r/it-service-management/incident-management/create-an-incident.html
    # https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials-grant-workflow.html
    return agent_watch.client_credentials_token(
        settings.origin + "/oauth_token.do",
        client_id=agent_watch.secret_named(settings.client_id_env, f"{_SECTION} client_id_env"),
        client_secret=agent_watch.secret_named(settings.client_secret_env, f"{_SECTION} client_secret_env"),
        scope="", timeout=_TIMEOUT,
    )


def _request(method: str, url: str, token: str, *, body: dict | None = None) -> dict | list:
    # Table GET, POST and PATCH, sysparm_fields/query/limit and the result format.
    # https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
    expected = (201,) if method == "POST" else (200,)
    status_code, raw = agent_watch._request(
        method, url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        timeout=_TIMEOUT, max_bytes=64 * 1024, json_body=body, ok=expected,
    )
    if status_code == 401:
        agent_watch._forget_token(token)
    if status_code not in expected:
        raise IncidentError(_RETRY_MESSAGE)
    answer = agent_watch._json_object(raw).get("result")
    if not isinstance(answer, (dict, list)):
        raise IncidentError(_RETRY_MESSAGE)
    return answer


def _verified(row: object, incident: Incident) -> tuple[str, str]:
    if not isinstance(row, dict) or row.get(_CORRELATION) != incident.correlation:
        raise IncidentError(_RETRY_MESSAGE)
    sys_id, state = row.get("sys_id"), row.get("state")
    if not isinstance(sys_id, str) or not _ID.fullmatch(sys_id) or not isinstance(state, str) or not state:
        raise IncidentError(_RETRY_MESSAGE)
    if incident.sys_id and sys_id != incident.sys_id:
        raise IncidentError(_RETRY_MESSAGE)
    return sys_id, state


def _incident_record(settings: Settings, incident: Incident, token: str, base: str) -> tuple[str, str]:
    # This custom field must carry a unique index on the Incident table. A
    # retry of an uncertain POST then cannot create a second incident.
    # https://www.servicenow.com/docs/r/platform-administration/table-administration-and-data-management/t_CreateCustomIndex.html
    fields = {"sysparm_fields": _FIELDS, "sysparm_display_value": "false"}
    if incident.sys_id:
        return _verified(_request("GET", f"{base}/{incident.sys_id}?{urlencode(fields)}", token), incident)
    query = urlencode({**fields, "sysparm_query": f"{_CORRELATION}={incident.correlation}", "sysparm_limit": 2})
    found = _request("GET", f"{base}?{query}", token)
    if not isinstance(found, list) or len(found) > 1:
        raise IncidentError(_RETRY_MESSAGE)
    if found:
        return _verified(found[0], incident)
    title = _TITLES[incident.event]
    description = title + "."
    if incident.event != "emergency":
        description += f" Agent reference {incident.subject[:12]}."
    body = {"short_description": title, "description": description, _CORRELATION: incident.correlation}
    if settings.caller_id:
        body["caller_id"] = settings.caller_id
    return _verified(_request("POST", f"{base}?{urlencode(fields)}", token, body=body), incident)


def _deliver(settings: Settings, incident: Incident) -> str:
    token = _token(settings)
    base = settings.origin + _TABLE_PATH
    # Read first to respect incidents a ServiceNow operator already resolved.
    sys_id, state = _incident_record(settings, incident, token, base)
    if not incident.resolve or state in {settings.resolved_state, settings.closed_state}:
        return sys_id
    # https://www.servicenow.com/docs/r/it-service-management/incident-management/resolve-and-close-an-incident.html
    # https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0727802
    patch = {"state": settings.resolved_state, "close_code": settings.close_code, "close_notes": _RESOLUTIONS[incident.event]}
    query = urlencode({"sysparm_fields": _FIELDS, "sysparm_display_value": "false"})
    saved_id, saved_state = _verified(_request("PATCH", f"{base}/{sys_id}?{query}", token, body=patch), incident)
    if saved_id != sys_id or saved_state not in {settings.resolved_state, settings.closed_state}:
        raise IncidentError(_RETRY_MESSAGE)
    return saved_id


def _due(settings: Settings) -> list[Incident]:
    blocked_keys: set[str] = set()
    due = []
    for row in _read(_path()):
        if row.delivered or row.origin != settings.origin or row.key in blocked_keys:
            continue
        blocked_keys.add(row.key)
        if row.retry_at <= _now():
            due.append(row)
    return due[:_BATCH_SIZE]


def _save_result(sent: Incident, sys_id: str) -> None:
    with _editing() as rows:
        row = next((item for item in rows if item.correlation == sent.correlation), None)
        if row is None:
            return
        if sys_id:
            row.sys_id = sys_id
            row.delivered = row.resolve == sent.resolve
            row.failures = 0
            row.retry_at = 0
        else:
            row.failures = min(row.failures + 1, 1000)
            row.retry_at = _now() + min(_RETRY_MAX, 30 * 2 ** min(row.failures - 1, 5))


def deliver_due() -> None:
    """Deliver a bounded batch. Errors retain the intent for the next pass."""
    from . import practice

    if practice.active() or not _DRAIN_LOCK.acquire(blocking=False):
        return
    try:
        settings = _settings()
        if settings is None or not _path().exists():
            return
        # Distinct from the short queue lock so event producers do not wait on
        # ServiceNow. A strict OS lock gives one sender for the data directory.
        with cross_process_lock(_path().with_suffix(".delivery"), strict=True):
            for row in _due(settings):
                try:
                    sys_id = _deliver(settings, row)
                except (IncidentError, agent_watch.WatchError, OSError):
                    sys_id = ""
                _save_result(row, sys_id)
    except Exception as exc:
        log.warning("ServiceNow incident queue could not be processed (%s)", type(exc).__name__)
    finally:
        _DRAIN_LOCK.release()


async def delivery_loop() -> None:
    """Keep the durable queue moving while the dashboard is running."""
    while True:
        await asyncio.to_thread(deliver_due)
        await asyncio.sleep(30)
