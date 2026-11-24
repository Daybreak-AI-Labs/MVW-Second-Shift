"""Telling people before something runs out: waiting requests and access keys.

Two things quietly stop working when nobody acts in time: a request waiting
for a decision (it runs out and the action is refused) and an agent's access
key (the agent can no longer work). This module sends, through
:func:`maverick.ops_alert.alert`:

* one reminder when a request is still waiting and only a set fraction of its
  time is left (and, when Microsoft Teams is on, a fresh card to the people
  who may decide it), and one note when it ran out undecided;
* one warning when an agent's access key will end within a set number of days,
  and one note when it has ended.

Each message goes out at most once per request or key. What was sent is kept as
a small record with the others (:mod:`maverick.record_documents`), so a restart
never sends it again. A
renewed key (a new end date) starts over. A message that no channel accepted is
not recorded, so the next pass tries again. Nothing here changes a request or a
key, and a failure is logged and never stops the app.

Settings (``~/.maverick/config.toml``)::

    [approval]
    reminder_fraction_left = 0.25   # remind when this share of the time is left; 0 = never

    [agent_keys]
    expiry_warning_days = 14        # warn this many days before a key ends; 0 = never

Only a request that carries a "decide by" time (the approval card of an
outside agent's action) can be reminded about; others do not run out.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

log = logging.getLogger("maverick.expiry_reminders")

DEFAULT_REMINDER_FRACTION = 0.25
DEFAULT_KEY_WARNING_DAYS = 14
#: A request that ran out longer ago than this is not announced (a long outage
#: or a new install must not flood people with old news).
_STALE_SECONDS = 24 * 3600
_KEEP = 2000
_DAY = 86400


def reminder_fraction() -> float:
    """``[approval] reminder_fraction_left``: the share of a request's time that
    is left when its reminder goes out. 0.25 by default, between 0 and 0.9;
    0 turns reminders off. An unusable value means the default."""
    return _number("approval", "reminder_fraction_left", DEFAULT_REMINDER_FRACTION, 0.0, 0.9)


def key_warning_days() -> int:
    """``[agent_keys] expiry_warning_days``: how many days before a key ends the
    warning goes out. 14 by default, between 0 and 365; 0 turns it off."""
    return int(_number("agent_keys", "expiry_warning_days", DEFAULT_KEY_WARNING_DAYS, 0, 365))


def _number(section: str, name: str, default: float, low: float, high: float) -> float:
    try:
        from .config import load_config
        raw = ((load_config() or {}).get(section) or {}).get(name)
    except Exception:  # noqa: BLE001 -- unreadable settings mean the defaults
        raw = None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw != raw:
        return default
    return max(low, min(high, float(raw)))


# ------------------------------------------------------------------- ledger

def _path():
    from .paths import data_dir
    return data_dir("expiry_reminders.json")


def _load() -> dict[str, dict]:
    from .record_documents import at

    text = at(_path()).read_text()
    if text is None:
        return {"approvals": {}, "keys": {}}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("the reminder record is not an object")
    return {"approvals": dict(data.get("approvals") or {}), "keys": dict(data.get("keys") or {})}


def sent_record() -> dict[str, dict]:
    """What has been sent, for tests and pages: ``{"approvals": ..., "keys": ...}``."""
    return _load()


def _mark(group: str, key: str, what: str, moment: float) -> None:
    from .record_documents import at

    record = at(_path())
    with record.locked():
        data = _load()
        data[group].setdefault(key, {})[what] = moment
        entries = data[group]
        if len(entries) > _KEEP:
            newest = sorted(entries.items(), key=lambda kv: max(kv[1].values(), default=0.0), reverse=True)
            data[group] = dict(newest[:_KEEP])
        record.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))


def _send(event: str, text: str, severity: str) -> bool:
    from .ops_alert import alert
    return bool(alert(event, text, severity=severity))


def _when(moment: float) -> str:
    return time.strftime("%d %B %Y at %H:%M UTC", time.gmtime(moment)).lstrip("0")


# ----------------------------------------------------------------- approvals

def _deadline(approval: Any) -> float | None:
    """The "decide by" time on a request's card, or ``None`` when it has none."""
    from .approval_cards import ApprovalCardError, decode_approval_detail
    try:
        card = decode_approval_detail(getattr(approval, "detail", None))
    except ApprovalCardError:
        return None
    return float(card["expires_at"]) if card else None


def _label(approval: Any) -> str:
    from .approval_cards import ApprovalCardError, decode_approval_detail
    try:
        card = decode_approval_detail(getattr(approval, "detail", None)) or {}
    except ApprovalCardError:
        card = {}
    text = " ".join(str(card.get("summary") or "").split())[:120]
    return text or "A request"


def check_approvals(world: Any = None, *, now: float | None = None) -> dict[str, list[int]]:
    """One pass over the requests still waiting. Returns the ids reminded and the
    ids announced as run out. Nothing is sent when alerts are off and Teams is
    off, so a later switch-on does not replay old reminders."""
    from . import approval_notify, ops_alert
    from .world_model import open_world

    moment = time.time() if now is None else float(now)
    out: dict[str, list[int]] = {"reminded": [], "expired": []}
    fraction = reminder_fraction()
    alerts_on = ops_alert.alerts_enabled()
    teams_on = approval_notify.teams_approvals_enabled()
    if not (alerts_on or teams_on):
        return out
    world = world if world is not None else open_world()
    sent = _load()["approvals"]
    for approval in world.pending_approvals():
        end = _deadline(approval)
        if end is None:
            continue
        key = f"{approval.id}:{int(approval.requested_at or 0)}"
        done = sent.get(key, {})
        window = end - float(approval.requested_at or 0)
        if moment >= end:
            if "expired" in done or moment - end > _STALE_SECONDS:
                continue
            text = (f"{_label(approval)} ran out on {_when(end)} before anyone decided it, "
                    "so it was refused. Ask for it again if it is still needed.")
            if alerts_on and _send("approval.expired", text, "warning"):
                _mark("approvals", key, "expired", moment)
                out["expired"].append(int(approval.id))
            continue
        if fraction <= 0 or window <= 0 or "reminder" in done or end - moment > fraction * window:
            continue
        text = (f"{_label(approval)} is still waiting for a decision and runs out on {_when(end)}. "
                "Open Approvals in Second Shift to decide it.")
        delivered = alerts_on and _send("approval.reminder", text, "high")
        if teams_on and approval_notify.approval_reminder(int(approval.id), world=world):
            delivered = True
        if delivered:
            _mark("approvals", key, "reminder", moment)
            out["reminded"].append(int(approval.id))
    return out


# ---------------------------------------------------------------------- keys

def check_keys(*, now: float | None = None) -> dict[str, list[str]]:
    """One pass over the access keys of enrolled agents. Returns the agents
    warned and the agents told their key has ended."""
    from . import agent_trust, external_agents, ops_alert

    moment = time.time() if now is None else float(now)
    out: dict[str, list[str]] = {"warned": [], "ended": []}
    days = key_warning_days()
    if not days or not external_agents.enabled() or not ops_alert.alerts_enabled():
        return out
    registry = agent_trust.load_registry(strict=True)
    names = {row["id"]: (row.get("description") or row["id"]) for row in external_agents.roster()}
    sent = _load()["keys"]
    for agent_id in sorted(names):
        entry = registry.get(agent_id)
        end = getattr(entry, "expires_at", None)
        if end is None or getattr(entry, "revoked", False):
            continue
        key = f"{agent_id}:{int(end)}"
        done = sent.get(key, {})
        name = " ".join(str(names[agent_id]).split())[:80]
        if moment >= end:
            if "ended" in done or moment - end > _STALE_SECONDS * 7:
                continue
            text = (f"The access key for {name} ended on {_when(end)}, so the agent can no longer work. "
                    "Create a new access key for it in Second Shift.")
            if _send("agent_key.expired", text, "high"):
                _mark("keys", key, "ended", moment)
                out["ended"].append(agent_id)
        elif end - moment <= days * _DAY and "warned" not in done:
            text = (f"The access key for {name} ends on {_when(end)}. "
                    "Create a new access key before then so the agent keeps working.")
            if _send("agent_key.expiring", text, "warning"):
                _mark("keys", key, "warned", moment)
                out["warned"].append(agent_id)
    return out


def check_all(*, now: float | None = None) -> None:
    """Both passes. One failing does not stop the other."""
    for step in (check_approvals, check_keys):
        try:
            step(now=now)
        except Exception:  # noqa: BLE001 -- a reminder never stops the app
            log.warning("expiry reminders: %s failed", step.__name__, exc_info=True)


__all__ = [
    "check_all",
    "check_approvals",
    "check_keys",
    "key_warning_days",
    "reminder_fraction",
    "sent_record",
]
