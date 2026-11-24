"""The audit trail page: read the signed audit log in plain words.

Lists entries newest first from the day-files the audit writer keeps, with
filters (dates, kind of event, agent, person), paging, an export of the
filtered entries, and an integrity check of the signed chain.

Every read is bounded: a day contributes at most ``DAY_ROWS`` of its newest
rows, a request examines at most ``SCAN_ROWS`` rows and a page is
``PAGE_SIZE`` entries. When a bound stops a read the page says so, so a short
list is never mistaken for a complete one.

The log is content-free by design and this module adds nothing to it: every
sentence is built from fields the row already holds, and the raw row is shown
as it is stored. Nothing here changes a record except the export, which writes
one row (``audit_exported``) before any data is sent; if that row cannot be
written, nothing is exported. The integrity check is expensive, so it runs only
when asked for (``GET /audit/integrity``), never when the page loads.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from .auth import auth_genuinely_off, caller_principal, require_permission

log = logging.getLogger(__name__)

PAGE_SIZE = 50
MAX_PAGE = 200
DAY_ROWS = 10_000
SCAN_ROWS = 20_000
EXPORT_MAX = 10_000
VERIFY_DAYS_DEFAULT = 30
VERIFY_DAYS_MAX = 90
RAW_MAX = 8_000
_TEXT_MAX = 200

#: The kinds of event a person can filter by, in the words shown to them.
GROUPS: tuple[tuple[str, str], ...] = (
    ("approvals", "Approvals"),
    ("agents", "Outside agents"),
    ("drift", "Drift"),
    ("platforms", "Platform checks"),
    ("signin", "Sign-in and roles"),
    ("settings", "Settings"),
    ("stop", "Emergency stop"),
    ("ekko", "Ekko"),
    ("audit", "The audit trail itself"),
    ("other", "Other"),
)
_GROUP_LABEL = dict(GROUPS)

_EXACT_GROUP = {
    "approval_decision": "approvals", "consent_prompt": "approvals", "consent_result": "approvals",
    "agent_trust_denied": "agents", "agent_trust_changed": "agents", "agent_edr_containment": "agents",
    "agent_baseline_approved": "drift",
    "access_grant_changed": "signin", "break_glass_token_used": "signin",
    "halt": "stop",
    "audit_exported": "audit",
    "webhook_subscription_changed": "settings", "capability_denied": "signin",
}
_PREFIX_GROUP = (
    ("external_", "agents"), ("agent_drift_", "drift"), ("model_", "drift"), ("agent_watch_", "platforms"),
    ("ekko_", "ekko"), ("approval_", "approvals"), ("sign_in", "signin"), ("session_", "signin"),
    ("login", "signin"), ("role_", "signin"),
)

#: Names the audit writer gives itself; an entry from one was made by Second
#: Shift on its own, not by a person.
_SYSTEM_WRITERS = frozenset({
    "system", "dashboard", "external_agents", "agent_drift", "agent_watch", "agent_trust",
    "agent_edr", "model_register", "control_plane", "notifications", "webhooks", "static-dashboard-operator",
})
_WHO_FIELDS = ("actor", "decided_by", "approved_by", "acknowledged_by", "enrolled_by",
               "contained_by", "released_by", "reset_by", "by")
_AGENT_FIELDS = ("external_agent", "trusted_agent", "peer", "agent_id")

_VERBS = {"suspend": "paused", "resume": "resumed", "contain": "blocked", "release": "let work again",
          "attenuate": "limited", "halt": "stopped", "clear-halt": "restarted"}
_TRUST = {"added": "added", "replaced": "replaced", "limits_changed": "changed the limits of",
          "blocked": "blocked", "unblocked": "unblocked", "removed": "removed"}


class AuditUnreadable(Exception):
    """The audit log could not be read, so nothing is shown from it."""


@dataclass(frozen=True)
class Filters:
    start: str = ""
    end: str = ""
    group: str = ""
    agent: str = ""
    person: str = ""
    page: int = 1

    def query(self, **change: Any) -> str:
        from urllib.parse import urlencode

        values = {"start": self.start, "end": self.end, "group": self.group, "agent": self.agent,
                  "person": self.person, "page": self.page, **change}
        return urlencode({key: value for key, value in values.items() if value not in ("", None, 1)})


def parse_filters(params: Any) -> Filters:
    """Filters from query or form values. A value that is not usable is
    refused in plain words rather than ignored, so a typo never shows more
    than was asked for."""
    from maverick.audit.events import is_valid_day

    def text(name: str) -> str:
        return " ".join(str(params.get(name) or "").split())[:80]

    start, end = text("start"), text("end")
    for label, value in (("start", start), ("end", end)):
        if value and not is_valid_day(value):
            raise HTTPException(400, f"The {label} date must look like 2026-11-24.")
    if start and end and start > end:
        raise HTTPException(400, "The start date is after the end date.")
    group = text("group")
    if group and group not in _GROUP_LABEL:
        raise HTTPException(400, "That kind of event is not one of the choices.")
    try:
        page = int(str(params.get("page") or "1"))
    except ValueError:
        raise HTTPException(400, "The page must be a number.") from None
    if not 1 <= page <= MAX_PAGE:
        raise HTTPException(400, f"The page must be between 1 and {MAX_PAGE}. Narrow the dates to reach older entries.")
    return Filters(start=start, end=end, group=group, agent=text("agent"), person=text("person"), page=page)


# ------------------------------------------------------------------ describing

def _text(row: dict, key: str) -> str:
    value = row.get(key)
    return " ".join(str(value).split())[:_TEXT_MAX] if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""


def group_of(row: dict) -> str:
    kind = str(row.get("kind") or "")
    if kind == "control_plane_action":
        return "stop" if str(row.get("verb") or "") in ("halt", "clear-halt") else "agents"
    if kind in _EXACT_GROUP:
        return _EXACT_GROUP[kind]
    for prefix, group in _PREFIX_GROUP:
        if kind.startswith(prefix):
            return group
    if kind.endswith("_changed") or kind.endswith("_updated"):
        return "settings"
    return "other"


def _who(row: dict) -> tuple[str, str]:
    """``(name, raw)`` of the person or service that did it."""
    from .identity_format import humanize_principal

    raw = next((_text(row, field) for field in _WHO_FIELDS if _text(row, field)), "")
    if not raw:
        writer = _text(row, "agent")
        raw = "" if writer in _SYSTEM_WRITERS or not writer else writer
    if not raw:
        return "Second Shift", ""
    return ("The local owner" if raw == "local:dashboard" else humanize_principal(raw).name), raw


def _agent(row: dict) -> str:
    found = next((_text(row, field) for field in _AGENT_FIELDS if _text(row, field)), "")
    if found:
        return found
    principal = _text(row, "principal")
    return principal if row.get("kind") == "control_plane_action" else ""


def _money(value: Any) -> str:
    try:
        return f"${float(value):,.2f}"
    except (TypeError, ValueError):
        return ""


def _sentence(row: dict, who: str, agent: str) -> str:  # noqa: C901 - one flat table of plain sentences
    kind = str(row.get("kind") or "")
    a = agent or "An agent"
    if kind == "approval_decision":
        verb = "approved" if row.get("status") == "approved" else "rejected"
        return f"{who} {verb} request {_text(row, 'approval_id')}."
    if kind == "consent_result":
        return f"A consent decision was recorded: {_text(row, 'decision') or 'no answer'}."
    if kind == "consent_prompt":
        return f"Consent was asked for a {_text(row, 'risk') or 'risky'} action."
    if kind == "external_agent_enrolled":
        return f"{who} added {a} ({_text(row, 'platform') or 'custom platform'})."
    if kind == "external_credential_minted":
        return f"An access key was created for {a} ({_text(row, 'surface')})."
    if kind == "external_run_started":
        return f"{a} started a task."
    if kind == "external_run_ingested":
        cost = _money(row.get("cost_dollars"))
        return f"{a} finished a task ({_text(row, 'outcome') or 'no outcome given'})" + (f", reported cost {cost}." if cost else ".")
    if kind == "external_action_screened":
        tool = _text(row, "tool") or "an action"
        if row.get("allowed") is True:
            return f"{a} was allowed to use {tool}."
        return f"{a} was refused {tool}" + (f": {_text(row, 'reason')}" if _text(row, "reason") else ".")
    if kind == "external_action_executed":
        return f"{a}'s action {_text(row, 'op')} through {_text(row, 'connector')} {_text(row, 'outcome')}."
    if kind == "external_agent_contained":
        return f"{a} was blocked for breaking rules."
    if kind == "external_agent_released":
        return f"{who} let {a} work again."
    if kind == "external_budget_reset":
        return f"{who} reset the spending of {a}."
    if kind == "agent_trust_denied":
        return f"{a} was refused" + (f": {_text(row, 'reason')}" if _text(row, "reason") else ".")
    if kind == "agent_trust_changed":
        return f"{who} {_TRUST.get(_text(row, 'action'), 'changed access for')} {a}."
    if kind == "agent_drift_detected":
        return f"Drift was found for {a} ({_text(row, 'finding_kind')}, {_text(row, 'severity')} severity)."
    if kind == "agent_drift_acknowledged":
        return f"{who} acknowledged a drift finding for {a}."
    if kind == "agent_drift_contained":
        return f"{a} was blocked after drift was found."
    if kind == "agent_baseline_approved":
        return f"{who} approved a new baseline for {a}."
    if kind == "agent_watch_synced":
        return (f"Platforms were checked: {_text(row, 'listed') or 0} agents found, "
                f"{_text(row, 'not_enrolled') or 0} not added here, {_text(row, 'failed') or 0} checks failed.")
    if kind == "control_plane_action":
        done = _VERBS.get(_text(row, "verb"), _text(row, "verb") or "changed")
        target = "everything" if _text(row, "principal") == "*" else a
        result = "" if row.get("ok") is not False else " This did not take effect."
        return f"{who} {done} {target}.{result}"
    if kind == "halt":
        return f"The emergency stop was {_text(row, 'operation') or 'used'} ({_text(row, 'source') or 'dashboard'})."
    if kind == "break_glass_token_used":
        return "The emergency administrator key was used."
    if kind == "access_grant_changed":
        return f"{who} changed who can do what."
    if kind == "webhook_subscription_changed":
        return f"{who} {_text(row, 'action') or 'changed'} a webhook subscription."
    if kind == "ekko_consent_changed":
        return f"Consent for Ekko was changed ({_text(row, 'state')})."
    if kind == "ekko_session":
        return f"An Ekko session changed ({_text(row, 'state')})."
    if kind == "ekko_mining_run":
        return f"Ekko looked for repeated work and found {_text(row, 'candidate_count') or 0}."
    if kind == "ekko_erase":
        return f"Ekko data was erased ({_text(row, 'scope')})."
    if kind == "audit_exported":
        return f"{who} exported {_text(row, 'entries') or 0} audit entries as {_text(row, 'format')}."
    from .identity_format import humanize

    return (humanize(kind) or "An event") + (f" by {who}." if who != "Second Shift" else ".")


def describe(row: dict, *, day: str = "") -> dict:
    """One row in plain words, with its raw fields kept for the page to offer."""
    who, who_raw = _who(row)
    agent = _agent(row)
    group = group_of(row)
    try:
        ts = float(row.get("ts"))
        when = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        ts, when = 0.0, day
    return {"ts": ts, "when": when, "kind": str(row.get("kind") or ""), "group": group,
            "group_label": _GROUP_LABEL[group], "who": who, "who_raw": who_raw, "agent": agent,
            "what": _sentence(row, who, agent), "row": row}


def raw_text(row: dict) -> str:
    """The row as stored, for the "raw fields" view."""
    raw = json.dumps(row, sort_keys=True, default=str, indent=2)
    return raw if len(raw) <= RAW_MAX else raw[:RAW_MAX] + "\n… (shortened here; the log holds the whole entry)"


# --------------------------------------------------------------------- reading

@dataclass
class Result:
    entries: list[dict]
    has_next: bool
    truncated: bool
    unreadable_days: list[str]


def audit_dir() -> Path:
    from maverick.audit import default_audit_log

    return Path(default_audit_log().audit_dir)


def _matches(entry: dict, filters: Filters) -> bool:
    if filters.group and entry["group"] != filters.group:
        return False
    if filters.agent and filters.agent.casefold() not in entry["agent"].casefold():
        return False
    if filters.person and filters.person.casefold() not in f"{entry['who']} {entry['who_raw']}".casefold():
        return False
    return True


def read(filters: Filters, *, want: int) -> Result:
    """The newest ``want`` entries that pass the filters (one more is read to
    know whether there is a next page), within the read bounds."""
    from maverick.audit.reader import tail_events
    from maverick.audit.segments import ReadReport
    from maverick.audit.signing import day_files

    root = audit_dir()
    try:
        if root.exists() and not root.is_dir():
            raise AuditUnreadable("The audit folder is not a folder.")
        days = day_files(root)
    except OSError as error:
        raise AuditUnreadable("The audit folder could not be listed.") from error
    chosen = [p for p in days if (not filters.start or p.stem >= filters.start) and (not filters.end or p.stem <= filters.end)]
    found: list[dict] = []
    scanned = 0
    truncated = False
    unreadable: list[str] = []
    for path in reversed(chosen):
        budget = SCAN_ROWS - scanned
        if budget <= 0:
            truncated = True
            break
        report = ReadReport()
        rows = tail_events(path, min(DAY_ROWS, budget), report=report)
        if report.failures:
            unreadable.append(path.stem)
        scanned += len(rows)
        if len(rows) >= min(DAY_ROWS, budget):
            truncated = True
        for row in reversed(rows):
            entry = describe(row, day=path.stem)
            if _matches(entry, filters):
                found.append(entry)
        if len(found) > want:
            break
    return Result(entries=found[:want + 1], has_next=len(found) > want, truncated=truncated, unreadable_days=unreadable)


def page_of(filters: Filters) -> Result:
    want = filters.page * PAGE_SIZE
    result = read(filters, want=want)
    start = (filters.page - 1) * PAGE_SIZE
    shown = result.entries[start:want]
    for entry in shown:
        entry["raw"] = raw_text(entry["row"])
    return Result(entries=shown, has_next=result.has_next, truncated=result.truncated,
                  unreadable_days=result.unreadable_days)


# ------------------------------------------------------------------- integrity

def verify(days: int = VERIFY_DAYS_DEFAULT) -> dict:
    """Check the signature chain of the newest ``days`` day-files. Never
    reports a pass for anything it could not check."""
    from maverick.audit.signing import day_files, verify_chain

    root = audit_dir()
    try:
        files = day_files(root)
    except OSError:
        return _verdict("unreadable", 0, 0, [])
    if not files:
        return _verdict("empty", 0, 0, [])
    chosen = files[-days:]
    problems: list[dict] = []
    for path in reversed(chosen):
        try:
            breaks = verify_chain(path, max_breaks=10)
        except Exception:  # noqa: BLE001 - fail closed: a check that cannot run is not a pass
            log.warning("audit check failed for %s", path.name, exc_info=True)
            problems.append({"day": path.stem, "reason": "unreadable", "line": 0})
            continue
        for found in breaks[:3]:
            problems.append({"day": path.stem, "reason": found.reason, "line": found.line_no})
    reasons = {p["reason"] for p in problems}
    if not problems:
        state = "intact"
    elif reasons <= {"unsigned"}:
        state = "unsigned"
    elif reasons <= {"unreadable", "unreadable_segment", "no_crypto", "no_pubkey", "missing_file"}:
        state = "unreadable"
    else:
        state = "broken"
    return _verdict(state, len(chosen), len(files), problems[:10])


_MEANING = {
    "intact": ("Passed. Every entry in the days checked is signed and chained to the one before it, so nothing was "
               "changed or removed after it was written."),
    "broken": ("Failed. Some entries do not match their signatures or no longer follow the entry before them, so they "
               "may have been changed or removed. Treat the days listed as not trustworthy and tell your security team."),
    "unsigned": ("Not proven. These days hold entries without signatures, so they cannot be shown to be unaltered. "
                 "An administrator can turn signing on."),
    "unreadable": ("Could not be checked. Some days could not be read or their signing keys were not available, so "
                   "nothing is claimed about them."),
    "empty": "Nothing to check yet: the audit trail has no entries.",
}


def _verdict(state: str, checked: int, total: int, problems: list[dict]) -> dict:
    if state == "unreadable" and not total and not problems:
        meaning = "Could not be checked. The audit folder could not be read."
    else:
        meaning = _MEANING[state]
    return {"state": state, "ok": state == "intact", "meaning": meaning, "days_checked": checked,
            "days_total": total, "problems": problems, "checked_at": time.time()}


# ---------------------------------------------------------------------- export

_FORMULA = re.compile(r"^[=+\-@\t\r]")


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if _FORMULA.match(text) else text


def _csv(entries: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(["When (UTC)", "Kind of event", "Who", "Agent", "What happened", "Event type", "Raw fields"])
    for e in entries:
        writer.writerow([_cell(e["when"]), _cell(e["group_label"]), _cell(e["who"]), _cell(e["agent"]), _cell(e["what"]),
                         _cell(e["kind"]), _cell(json.dumps(e["row"], sort_keys=True, default=str))])
    return out.getvalue()


def _json(entries: list[dict], filters: Filters, truncated: bool) -> str:
    rows = []
    for e in entries:
        rows.append({"when": e["when"], "kind_of_event": e["group_label"], "who": e["who"], "agent": e["agent"],
                     "what": e["what"], "event_type": e["kind"], "raw": e["row"]})
    return json.dumps({"filters": {"start": filters.start, "end": filters.end, "kind_of_event": filters.group,
                                   "agent": filters.agent, "person": filters.person},
                       "truncated": truncated, "entries": rows}, indent=2, default=str)


def _exporter(request: Request) -> str:
    principal = str(caller_principal(request) or "")
    if principal:
        return principal
    if auth_genuinely_off():
        return "local:dashboard"
    raise HTTPException(403, "An export needs a signed-in person, so it can be recorded against them.")


def export(request: Request, filters: Filters, fmt: str) -> Response:
    """Export the filtered entries. The export is recorded first; if it cannot
    be recorded, nothing is sent."""
    from maverick.audit import AuditRefused, audit_event

    if fmt not in ("csv", "json"):
        raise HTTPException(400, "The format must be csv or json.")
    actor = _exporter(request)
    try:
        result = read(filters, want=EXPORT_MAX)
    except AuditUnreadable as error:
        raise HTTPException(503, f"{error} Nothing was exported.") from error
    entries = result.entries[:EXPORT_MAX]
    cut = result.truncated or result.has_next or bool(result.unreadable_days)
    try:
        recorded = audit_event(
            "audit_exported", agent="dashboard", actor=actor, format=fmt, entries=len(entries),
            start=filters.start, end=filters.end, kind_of_event=filters.group,
            filtered_by_agent=bool(filters.agent), filtered_by_person=bool(filters.person))
    except AuditRefused:
        recorded = False
    if not recorded:
        raise HTTPException(503, "The export could not be recorded in the audit trail, so nothing was exported.")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    body = _csv(entries) if fmt == "csv" else _json(entries, filters, cut)
    return Response(
        body, media_type="text/csv; charset=utf-8" if fmt == "csv" else "application/json",
        headers={"Content-Disposition": f'attachment; filename="second-shift-audit-{stamp}.{fmt}"',
                 "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"})


# ---------------------------------------------------------------------- routes

def _href(filters: Filters, page: int) -> str:
    query = filters.query(page=page)
    return "/audit?" + query if query else "/audit"


def create_audit_page_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["audit-trail-page"])

    @router.get("/audit", response_class=HTMLResponse, include_in_schema=False)
    async def audit_page(request: Request) -> HTMLResponse:
        require_permission(request, "audit")
        filters = parse_filters(request.query_params)
        problem = ""
        result = Result([], False, False, [])
        try:
            result = await run_in_threadpool(page_of, filters)
        except AuditUnreadable as error:
            problem = f"{error} Nothing is shown until it can be read."
        return templates.TemplateResponse(
            request, "audit.html",
            {"filters": filters, "groups": GROUPS, "result": result, "problem": problem, "page_size": PAGE_SIZE,
             "export_max": EXPORT_MAX, "verify_days": VERIFY_DAYS_DEFAULT,
             "previous_href": _href(filters, filters.page - 1) if filters.page > 1 else "",
             "next_href": _href(filters, filters.page + 1) if result.has_next and filters.page < MAX_PAGE else ""},
            status_code=503 if problem else 200,
            headers={"Cache-Control": "private, no-store"})

    @router.get("/audit/integrity", include_in_schema=False)
    async def audit_integrity(request: Request, days: int = VERIFY_DAYS_DEFAULT) -> JSONResponse:
        require_permission(request, "audit")
        if not 1 <= days <= VERIFY_DAYS_MAX:
            raise HTTPException(400, f"Check between 1 and {VERIFY_DAYS_MAX} days.")
        return JSONResponse(await run_in_threadpool(verify, days), headers={"Cache-Control": "private, no-store"})

    @router.post("/audit/export", include_in_schema=False)
    async def audit_export(request: Request) -> Response:
        require_permission(request, "audit")
        form = await request.form()
        return await run_in_threadpool(export, request, parse_filters(form), str(form.get("format") or ""))

    return router
