"""The weekly note to each agent owner: what needs them, once a week.

Every owner of an enrolled agent (an email address on the agent's record) gets
at most one email per week listing only what needs them: agents that changed on
their platform, unacknowledged changes in behaviour or in a model, agents
blocked or paused, spending above 80% of the limit, access keys ending soon,
requests about their agents still waiting, and agents nobody has heard from.
When nothing needs an owner, nothing is sent. With Microsoft Teams on and
``teams = true`` the same short list also goes to the owner's own Teams chat.

The note says what and where, never what an agent said or was asked: no
prompts, outputs, request details, finding text or secrets, only counts, agent
names and links to the pages. It is sent through
:func:`maverick.notifications.send_email`, whose recipient, TLS and sign-in
handling are not changed here.

Settings (``~/.maverick/config.toml``)::

    [owner_note]
    enabled = false          # off until an administrator turns it on
    weekday = "monday"       # the day it goes out
    hour = 8                 # the hour (0-23) in the time zone below
    timezone = "UTC"         # an IANA name such as "Europe/London"
    teams = false            # also message the owner in Teams when Teams is on

The note also needs alerts by email to be set up (the same mail settings the
alerts use); without them nothing is sent.

What was sent is kept per owner and week in the record ``owner_notes.json``, with the
other records (``maverick.record_documents``), under a one-way digest of the address, so a restart never sends
a note twice. A note that was being handed to the mail server when the app
stopped is not repeated. A pass run within :data:`GRACE_SECONDS` after the
scheduled time still sends, so a short outage does not skip a week.
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

log = logging.getLogger("maverick.owner_note")

WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
DEFAULT_WEEKDAY = "monday"
DEFAULT_HOUR = 8
DEFAULT_TIMEZONE = "UTC"
#: How long after its scheduled time a week's note may still go out.
GRACE_SECONDS = 12 * 3600
#: A failed hand-over is tried again no sooner than this.
_RETRY_SECONDS = 30 * 60
_KEEP = 5000

#: What each kind of item is called in the note, in the order they are listed.
SECTIONS = (
    ("platform", "Changed on their platform"),
    ("drift", "Changes in behaviour or set-up that nobody has acknowledged"),
    ("models", "Changes in the models they use that nobody has acknowledged"),
    ("blocked", "Blocked or paused"),
    ("spend", "Spending above 80% of the limit"),
    ("key", "Access key ending or ended"),
    ("requests", "Requests waiting for a decision"),
    ("silent", "Nobody has heard from them yet"),
)


# ----------------------------------------------------------------- settings

def settings() -> dict:
    """The ``[owner_note]`` table with defaults, and ``problems``: plain
    sentences about values that could not be used (the defaults apply)."""
    from ._envparse import coerce_bool

    try:
        from .config import load_config

        table = (load_config() or {}).get("owner_note")
    except Exception:  # noqa: BLE001 -- unreadable settings leave the note off
        return {"enabled": False, "weekday": 0, "weekday_name": DEFAULT_WEEKDAY, "hour": DEFAULT_HOUR,
                "timezone": DEFAULT_TIMEZONE, "teams": False,
                "problems": ["The settings could not be read, so the weekly note is off."]}
    table = table if isinstance(table, dict) else {}
    problems: list[str] = []
    name = str(table.get("weekday", DEFAULT_WEEKDAY)).strip().casefold()
    match = [d for d in WEEKDAYS if d == name or (len(name) >= 3 and d.startswith(name))]
    if not match:
        problems.append(f"The weekday \"{str(table.get('weekday'))[:30]}\" is not a day of the week; Monday is used.")
    day = match[0] if match else DEFAULT_WEEKDAY
    hour = table.get("hour", DEFAULT_HOUR)
    if isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23:
        problems.append("The hour must be a whole number from 0 to 23; 8 is used.")
        hour = DEFAULT_HOUR
    zone = str(table.get("timezone") or DEFAULT_TIMEZONE).strip()
    if _zone(zone) is None:
        problems.append(f"The time zone \"{zone[:40]}\" is not known; UTC is used.")
        zone = DEFAULT_TIMEZONE
    return {"enabled": coerce_bool(table.get("enabled"), False), "weekday": WEEKDAYS.index(day),
            "weekday_name": day, "hour": hour, "timezone": zone,
            "teams": coerce_bool(table.get("teams"), False), "problems": problems}


def _zone(name: str):
    from zoneinfo import ZoneInfo

    if name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 -- unknown or unreadable zone
        return None


def scheduled_slot(now: float, cfg: dict) -> datetime:
    """The latest scheduled time at or before ``now``, in the note's time zone."""
    zone = _zone(cfg["timezone"]) or timezone.utc
    local = datetime.fromtimestamp(now, zone)
    back = (local.weekday() - cfg["weekday"]) % 7
    slot = (local - timedelta(days=back)).replace(hour=cfg["hour"], minute=0, second=0, microsecond=0)
    if slot > local:
        slot -= timedelta(days=7)
    return slot


def email_ready() -> tuple[bool, str]:
    """Whether alerts by email are set up, and if not why."""
    try:
        from .notifications import backend_status

        status = backend_status("email")
    except Exception:  # noqa: BLE001
        return False, "The mail settings could not be read."
    return bool(status["ready"]), str(status.get("problem") or "")


def teams_ready() -> bool:
    try:
        from .approval_notify import teams_approvals_enabled

        return bool(teams_approvals_enabled())
    except Exception:  # noqa: BLE001
        return False


def status(now: float | None = None) -> dict:
    """Whether the note will go out and when next, for a settings page."""
    cfg = settings()
    ready, problem = email_ready()
    moment = time.time() if now is None else float(now)
    slot = scheduled_slot(moment, cfg)
    following = slot + timedelta(days=7)
    return {**cfg, "email_ready": ready, "email_problem": problem, "active": cfg["enabled"] and ready,
            "next_at": following.timestamp(), "teams_ready": teams_ready()}


# ------------------------------------------------------------------- ledger

def _path():
    from .paths import data_dir

    return data_dir("owner_notes.json")


def _load() -> dict[str, dict]:
    from .record_documents import at

    text = at(_path()).read_text()
    if text is None:
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("the weekly note record is not an object")
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def sent_record() -> dict[str, dict]:
    """What the weekly note has done, for tests and pages: key to state."""
    return _load()


def _key(address: str, week: str, channel: str) -> str:
    digest = hashlib.sha256(address.encode("utf-8")).hexdigest()[:24]
    return f"{digest}|{week}|{channel}"


def _claim(key: str, moment: float) -> bool:
    """Take this owner's week for one attempt. False when it is already done,
    or in progress, or failed too recently to try again."""
    from .record_documents import at

    with at(_path()).locked():
        data = _load()
        before = data.get(key)
        if before:
            if before.get("state") != "failed" or moment - float(before.get("at") or 0) < _RETRY_SECONDS:
                return False
        data[key] = {"state": "sending", "at": moment}
        _store(data)
    return True


def _store(data: dict) -> None:
    from .record_documents import at

    if len(data) > _KEEP:
        newest = sorted(data.items(), key=lambda kv: float(kv[1].get("at") or 0), reverse=True)
        data = dict(newest[:_KEEP])
    at(_path()).write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))


def _finish(key: str, state: str, moment: float) -> None:
    from .record_documents import at

    with at(_path()).locked():
        data = _load()
        data[key] = {"state": state, "at": moment}
        _store(data)


def _done(key: str) -> bool:
    entry = _load().get(key)
    return bool(entry) and entry.get("state") in ("sent", "empty", "sending", "skipped")


# ------------------------------------------------------------------ content

def _link(path: str) -> str:
    try:
        from .webhook_events import record_link

        return record_link(path)
    except Exception:  # noqa: BLE001 -- the link is a convenience
        return path


def collect(views: list[dict], now: float) -> dict[str, list[dict]]:
    """Group one owner's agent views by kind of item, in note order. A kind
    with nothing is left out."""
    from .agent_owners import attention

    groups: dict[str, list[dict]] = {}
    for view in views:
        for kind in attention(view, now):
            groups.setdefault(kind, []).append(view)
    return {kind: groups[kind] for kind, _title in SECTIONS if kind in groups}


def _detail(kind: str, view: dict) -> str:
    if kind == "platform":
        return "no longer found on its platform" if view["platform"]["missing"] else (
            f"{view['drift']['changed_on_platform']} unacknowledged "
            f"{'change' if view['drift']['changed_on_platform'] == 1 else 'changes'}")
    if kind == "drift":
        count = view["drift"]["open"] - view["drift"]["changed_on_platform"]
        return f"{count} unacknowledged {'change' if count == 1 else 'changes'}"
    if kind == "models":
        count = view["models"]["open"]
        return f"{count} unacknowledged {'change' if count == 1 else 'changes'} in the models it uses"
    if kind == "blocked":
        return view["lifecycle_label"].lower()
    if kind == "spend":
        spend = view["spend"]
        return f"{round(spend['share'] * 100)}% of its limit used {spend['period']}"
    if kind == "key":
        end = view["key"]["expires_at"]
        when = time.strftime("%d %B %Y", time.gmtime(end)).lstrip("0") if end else ""
        return f"access key {'ended' if view['key']['state'] == 'ended' else 'ends'} on {when}"
    if kind == "requests":
        count = view["waiting"]["count"]
        return f"{count} {'request' if count == 1 else 'requests'} waiting"
    return "not heard from yet"


def compose(address: str, groups: dict[str, list[dict]]) -> tuple[str, str, str]:
    """``(subject, text, html)`` for one owner. Nothing but agent names, counts
    and links goes in: no prompts, outputs, finding text, ids of requests or
    secrets."""
    agents = {v["id"] for views in groups.values() for v in views}
    subject = (f"Second Shift: {len(agents)} of your agents need you this week" if len(agents) != 1
               else "Second Shift: one of your agents needs you this week")
    mine = _link("/my-agents")
    text = ["These agents list you as their owner and need your attention this week.", ""]
    parts = ["<p>These agents list you as their owner and need your attention this week.</p>"]
    for kind, title in SECTIONS:
        views = groups.get(kind)
        if not views:
            continue
        text.append(title)
        parts.append(f"<h3 style=\"margin:16px 0 4px\">{html.escape(title)}</h3><ul>")
        for view in views:
            link = _link("/external-agents/" + quote(view["id"], safe=""))
            line = f"{view['name']}: {_detail(kind, view)}"
            text.append(f"  - {line}\n    {link}")
            parts.append(f"<li><a href=\"{html.escape(link, quote=True)}\">{html.escape(view['name'])}</a>: "
                         f"{html.escape(_detail(kind, view))}</li>")
        parts.append("</ul>")
        text.append("")
    text += [f"See all your agents: {mine}", "",
             "You get this note once a week, and only when something needs you. "
             "An administrator can turn it off."]
    parts.append(f"<p><a href=\"{html.escape(mine, quote=True)}\">See all your agents</a></p>"
                 "<p style=\"color:#555\">You get this note once a week, and only when something needs you. "
                 "An administrator can turn it off.</p>")
    body = "<html><body style=\"font-family:sans-serif\">" + "".join(parts) + "</body></html>"
    return subject, "\n".join(text), body


def teams_text(groups: dict[str, list[dict]]) -> str:
    agents = sorted({v["name"] for views in groups.values() for v in views})
    shown = ", ".join(agents[:5]) + (f" and {len(agents) - 5} more" if len(agents) > 5 else "")
    return (f"Second Shift: {len(agents)} of your {'agent needs' if len(agents) == 1 else 'agents need'} "
            f"you this week ({shown}). See what to do: {_link('/my-agents')}")


# ------------------------------------------------------------------ sending

def _send_teams(address: str, groups: dict[str, list[dict]]) -> str:
    """Message the owner in their own Teams chat: ``"sent"``, ``"skipped"`` when
    Teams does not know them (nothing to retry) or ``"failed"``. Never raises."""
    try:
        from maverick_dashboard import teams_bot

        from . import agent_owners, teams_identity
        from .approval_notify import teams_settings

        bot = teams_bot.build_bot()
        if bot is None:
            return "skipped"
        principal = teams_identity.resolve_principal(agent_owners.object_id_of(address), address)
        if not principal:
            return "skipped"
        allowed = teams_settings()["allowed_users"]
        sent = False
        for person in teams_identity.reachable_people():
            if person["principal"] != principal or (allowed and person["teams_id"] not in allowed):
                continue
            conversation = person.get("conversation") or {}
            service_url = conversation.get("service_url") or teams_bot._service_url(bot.settings)
            conversation_id = conversation.get("conversation_id") or bot.connector.create_personal_conversation(
                service_url, member_id=person["teams_id"], tenant_id=bot.settings["tenant_id"])
            bot.connector.send_activity(service_url, conversation_id, {"text": teams_text(groups)})
            sent = True
        return "sent" if sent else "skipped"
    except Exception as exc:  # noqa: BLE001 -- Teams never stops the email or the app
        log.warning("owner note: Teams message failed (%s)", type(exc).__name__)
        return "failed"


def run_due(*, now: float | None = None) -> dict[str, list[str]]:
    """One pass: send this week's note to each owner that has something to
    deal with and has not had one. Returns ``{"emailed": [...], "teams": [...],
    "nothing": [...]}`` as digests of owners, never addresses. Does nothing
    when the note is off, mail is not set up, or the week's time has not come
    (or went by more than :data:`GRACE_SECONDS` ago)."""
    from . import agent_owners, notifications

    out: dict[str, list[str]] = {"emailed": [], "teams": [], "nothing": []}
    cfg = settings()
    if not cfg["enabled"] or not email_ready()[0]:
        return out
    moment = time.time() if now is None else float(now)
    slot = scheduled_slot(moment, cfg)
    if not 0 <= moment - slot.timestamp() <= GRACE_SECONDS:
        return out
    week = slot.date().isoformat()
    teams_on = cfg["teams"] and teams_ready()
    for address, views in agent_owners.by_owner(now=moment).items():
        who = _key(address, week, "")[:24]  # a digest, never the address
        email_key, teams_key = _key(address, week, "email"), _key(address, week, "teams")
        if _done(email_key) and (not teams_on or _done(teams_key)):
            continue
        groups = collect(views, moment)
        if not groups:
            if _claim(email_key, moment):
                _finish(email_key, "empty", moment)
                out["nothing"].append(who)
            continue
        if not _done(email_key) and _claim(email_key, moment):
            subject, text, body = compose(address, groups)
            delivered = notifications.send_email(address, subject, text, html_body=body)
            _finish(email_key, "sent" if delivered else "failed", moment)
            if delivered:
                out["emailed"].append(who)
        if teams_on and _claim(teams_key, moment):
            result = _send_teams(address, groups)
            _finish(teams_key, result, moment)
            if result == "sent":
                out["teams"].append(who)
    return out


__all__ = [
    "GRACE_SECONDS",
    "SECTIONS",
    "collect",
    "compose",
    "email_ready",
    "run_due",
    "scheduled_slot",
    "sent_record",
    "settings",
    "status",
    "teams_text",
]
