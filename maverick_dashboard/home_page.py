"""The home page: what needs the signed-in person today.

One page that gathers, for the person looking at it, everything that is waiting
on them, each item linking to the place where it is dealt with. It shows only
what that person's permissions allow (``approve``, ``view``, ``admin``), newest
and most serious first.

Every source is read on its own. A source that cannot be read becomes one plain
line in its own section and the rest of the page still renders, so no section
can take the page down. Nothing is cached between requests, and the page only
reads: it never runs a drift check, a platform check or sends an alert, and it
changes no record.

What this module does not do: decide anything, change a setting, or hold state.
Acting on an item happens on the page the item links to.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from .auth import has_permission

log = logging.getLogger(__name__)

#: How many items a section lists; the section says how many there are in all.
SHOWN = 5
#: At most this many agents have their drift findings read for the page.
DRIFT_AGENTS_READ = 25

_RANK = {"high": 3, "medium": 2, "low": 1}
_RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_DRIFT_RANK = {"high": 3, "medium": 2, "low": 1}

_AGENTS_PAGE = "/external-agents"
_CHANNELS = {"teams": "Teams", "email": "email"}


def _plural(count: int, one: str, many: str | None = None) -> str:
    return f"{count} {one if count == 1 else (many or one + 's')}"


def _day(moment: float) -> str:
    when = datetime.fromtimestamp(moment, tz=timezone.utc)
    return f"{when.day} {when:%b %Y}"


def _agent_name(agent: dict) -> str:
    return str(agent.get("description") or agent.get("id") or "An agent")


def _allowed(request: Request, permission: str) -> bool:
    """Whether the caller holds ``permission``. A permission that cannot be
    checked is not held."""
    try:
        return bool(has_permission(request, permission))
    except Exception:  # noqa: BLE001 - fail closed: an unreadable role shows nothing
        log.warning("home page: permission check failed", exc_info=True)
        return False


def _section(key: str, title: str, link: str, link_label: str) -> dict:
    return {"key": key, "title": title, "link": link, "link_label": link_label,
            "lines": [], "count": 0, "error": "", "watching": ""}


def _read(section: dict, error: str, source: Callable[[dict], None]) -> dict:
    """Fill ``section`` from ``source``; if it fails say so in plain words."""
    try:
        source(section)
    except Exception:  # noqa: BLE001 - one source failing must not take the page down
        log.warning("home page: %s could not be read", section["key"], exc_info=True)
        section.update(lines=[], count=0, watching="", error=error)
    return section


def _order(items: list[dict]) -> list[dict]:
    """Most serious first, then newest first."""
    return sorted(items, key=lambda item: (-_RANK.get(item["severity"], 0), -float(item.get("at") or 0)))


# ------------------------------------------------------------------- sources

def _approvals(section: dict, request: Request) -> None:
    from maverick.safety.secret_detector import redact

    from ._shared import _world
    from .content_access import can_read_approval
    from .identity_format import humanize

    world = _world()
    waiting = [row for row in world.pending_approvals() if can_read_approval(request, row, world)]
    items = []
    for row in waiting:
        action = " ".join(str(row.action or "").split())
        parts = action.split(":")
        agent = parts[1] if (row.provenance == "external_agents" and len(parts) == 3 and parts[0] == "external") else ""
        title = humanize(parts[2] if agent else action) or "A request"
        risk = str(row.risk or "")
        who = f"From {agent}. " if agent else ""
        items.append({
            "text": redact(title)[0][:200],
            "detail": f"{who}{humanize(risk) or 'Unrated'} risk, asked {_day(float(row.requested_at))}.",
            "href": f"/approvals#approval-{row.id}",
            "severity": "high" if risk in ("high", "critical") else "medium",
            "at": float(row.requested_at or 0),
            "risk": _RISK_RANK.get(risk, 0),
        })
    items.sort(key=lambda item: (-item["risk"], -item["at"]))
    section.update(lines=items[:SHOWN], count=len(items), watching="requests waiting for a decision")


def _agents_enabled() -> bool:
    from maverick import external_agents

    return bool(external_agents.enabled())


def _drift(section: dict) -> None:
    from maverick import agent_drift, external_agents

    if not _agents_enabled() or not agent_drift.enabled():
        return
    try:
        names = {row["id"]: _agent_name(row) for row in external_agents.roster()}
    except Exception:  # noqa: BLE001 - names are a convenience; the findings do not depend on them
        names = {}
    rows = [row for row in agent_drift.roster_view() if row["findings_count"] > 0]
    rows.sort(key=lambda row: (-_DRIFT_RANK.get(row["highest_severity"], 0), -float(row["last_observed_at"] or 0)))
    items: list[dict] = []
    total = 0
    for position, row in enumerate(rows):
        total += int(row["findings_count"])
        if len(items) >= SHOWN * 2 or position >= DRIFT_AGENTS_READ:
            continue
        agent_id = row["agent_id"]
        for finding in agent_drift.detail(agent_id)["findings"]:
            if finding.get("acknowledged"):
                continue
            items.append({
                "text": f"{names.get(agent_id, agent_id)}: {finding['summary']}"[:300],
                "detail": "Differs from the behaviour you approved.",
                "href": f"{_AGENTS_PAGE}/{agent_id}#agent-drift",
                "severity": finding["severity"] if finding["severity"] in _RANK else "medium",
                "at": float(finding.get("reported_at") or row["last_observed_at"] or 0),
            })
    section.update(lines=_order(items)[:SHOWN], count=total, watching="changes in how agents behave")


def _blocked_agents(section: dict) -> None:
    from maverick import external_agents, revocation

    if not _agents_enabled():
        return
    roster = external_agents.roster()
    paused = set(revocation.shared().revoked())
    items = []
    for agent in roster:
        reasons = []
        if agent["contained"]:
            reasons.append("blocked for breaking rules")
        if agent["over_budget"]:
            reasons.append("over its budget")
        is_paused = f"agent:{agent['id']}" in paused or agent["lifecycle"] == "suspended"
        if is_paused:
            reasons.append("paused")
        if not reasons:
            continue
        said = "; ".join(reasons)
        items.append({
            "text": f"{_agent_name(agent)} is {said}.",
            "detail": "It cannot do its work until this is dealt with." if agent["contained"] or is_paused
                      else "Its spending passed the limit you set.",
            "href": f"{_AGENTS_PAGE}/{agent['id']}",
            "severity": "high" if agent["contained"] else "medium",
            "at": float(agent.get("last_run_at") or agent.get("last_seen") or 0),
        })
    section.update(lines=_order(items)[:SHOWN], count=len(items),
                   watching=_plural(len(roster), "outside agent") + " for rule breaks, spending and pauses")


def _platforms(section: dict) -> None:
    from maverick import agent_watch, external_agents

    if not _agents_enabled() or not agent_watch.enabled():
        return
    status = agent_watch.status()
    claimed = {str(agent.get("external_ref") or "").casefold() for agent in external_agents.roster()} - {""}
    found = agent_watch.unenrolled()
    waiting = [entry for entry in found if entry["external_ref"].casefold() not in claimed]
    link = f"{_AGENTS_PAGE}#platform-checks"
    items = []
    for platform in status["platforms"]:
        name = _platform_label(platform["name"])
        if not platform["ready"]:
            items.append({"text": f"{name}: the settings need attention.", "detail": platform["problem"],
                          "href": link, "severity": "high", "at": float(platform["last_attempt_at"] or 0)})
        elif platform["failures_in_a_row"]:
            items.append({"text": f"{name}: the last check failed.", "detail": platform["last_error"],
                          "href": link, "severity": "high", "at": float(platform["last_error_at"] or 0)})
    count = len(items)
    missing = max(0, int(status["missing_count"]))
    if missing:
        count += 1
        items.append({"text": f"{_plural(missing, 'agent')} added here no longer {'is' if missing == 1 else 'are'} on {'its' if missing == 1 else 'their'} platform.",
                      "detail": "Check whether it was removed on purpose.", "href": link, "severity": "medium", "at": 0.0})
    hidden = max(0, int(status["not_enrolled_count"]) - (len(found) - len(waiting)))
    count += hidden
    for entry in waiting:
        items.append({"text": f"{entry['name'] or entry['external_id']} is on {_platform_label(entry['platform'])} but nobody added it here.",
                      "detail": "It works outside your rules until you add it.", "href": link,
                      "severity": "medium", "at": float(entry["first_seen_at"] or 0)})
    section.update(lines=_order(items)[:SHOWN], count=count, watching="your platforms for failed checks and agents nobody added")


def _platform_label(name: str) -> str:
    from .identity_format import humanize

    return humanize(name)


def _keys(section: dict) -> None:
    from maverick import agent_trust, external_agents

    if not _agents_enabled():
        return
    roster = {agent["id"]: agent for agent in external_agents.roster()}
    registry = agent_trust.load_registry(strict=True)
    from maverick.expiry_reminders import key_warning_days

    now = time.time()
    # The same window the expiry warnings use; 0 turns the warning off, but
    # keys that have already ended are still listed.
    horizon = now + key_warning_days() * 86400
    items = []
    for agent_id, agent in roster.items():
        entry = registry.get(agent_id)
        ends = getattr(entry, "expires_at", None)
        if ends is None or getattr(entry, "revoked", False) or ends > horizon:
            continue
        name = _agent_name(agent)
        gone = ends <= now
        items.append({
            "text": f"{name}'s access ended on {_day(ends)}." if gone else f"{name}'s access ends on {_day(ends)}.",
            "detail": "It can no longer work. Create a new access key." if gone else "Create a new access key before then.",
            "href": f"{_AGENTS_PAGE}/{agent_id}",
            "severity": "high" if gone or ends - now <= 3 * 86400 else "medium",
            "at": now - float(ends),  # among equals, the soonest to end comes first
        })
    section.update(lines=_order(items)[:SHOWN], count=len(items), watching="when access keys end")


def _alerts(section: dict) -> None:
    from maverick import ops_alert

    status = ops_alert.delivery_status()
    link = f"{_AGENTS_PAGE}#alert-delivery"
    items = []
    if not status["enabled"]:
        items.append({"text": "Alerts are switched off.", "href": link, "severity": "high", "at": 0.0,
                      "detail": "A blocked agent or a drift finding is still recorded, but nobody is told when it happens."})
    elif not status["channels"]:
        items.append({"text": "Alerts are on but have nowhere to go.", "href": link, "severity": "high", "at": 0.0,
                      "detail": "Set up Teams or email so alerts reach someone."})
    else:
        for channel in status["channels"]:
            if not channel.get("ready"):
                items.append({"text": f"Alerts by {_CHANNELS.get(channel.get('channel'), channel.get('channel'))} are not ready.", "href": link, "severity": "medium",
                              "at": 0.0, "detail": str(channel.get("problem") or "")})
    section.update(lines=items, count=len(items), watching="that alerts can reach people")


# --------------------------------------------------------------------- page

_ERRORS = {
    "approvals": "Requests waiting for a decision could not be read.",
    "drift": "Drift findings could not be read.",
    "agents": "Outside agents could not be read.",
    "platforms": "Platform checks could not be read.",
    "keys": "Access key dates could not be read.",
    "alerts": "Alert settings could not be read.",
}


def build(request: Request) -> dict[str, Any]:
    """What the page shows this caller: sections in the order a person should
    work through them, and the lines that say what was and was not read."""
    plan: list[tuple[str, str, str, str, str, Callable[[dict], None]]] = []
    if _allowed(request, "approve"):
        plan.append(("approvals", "Waiting for your decision", "/approvals", "Open approvals", "approve",
                     lambda s: _approvals(s, request)))
    if _allowed(request, "view"):
        plan.append(("drift", "Agents behaving differently", _AGENTS_PAGE, "Open outside agents", "view", _drift))
        plan.append(("agents", "Agents that are blocked, over budget or paused", _AGENTS_PAGE, "Open outside agents", "view",
                     _blocked_agents))
        plan.append(("platforms", "Found on your platforms", f"{_AGENTS_PAGE}#platform-checks", "Open platform checks", "view",
                     _platforms))
    if _allowed(request, "admin"):
        plan.append(("keys", "Access keys that are ending", _AGENTS_PAGE, "Open outside agents", "admin", _keys))
        plan.append(("alerts", "Alerts", f"{_AGENTS_PAGE}#alert-delivery", "Open alert settings", "admin", _alerts))
    sections = [_read(_section(key, title, link, label), _ERRORS[key], source)
                for key, title, link, label, _perm, source in plan]
    needing = sum(s["count"] for s in sections)
    failed = [s["error"] for s in sections if s["error"]]
    watching = [s["watching"] for s in sections if s["watching"]]
    return {
        "sections": sections,
        "attention": needing,
        "failed": failed,
        "watching": watching,
        "all_clear": needing == 0 and not failed,
        "can_audit": _allowed(request, "audit"),
        "can_approve": any(s["key"] == "approvals" for s in sections),
    }
