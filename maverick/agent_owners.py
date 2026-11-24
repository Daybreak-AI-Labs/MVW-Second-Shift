"""Who owns which outside agent, and what each owner's agents look like now.

Every enrolled agent records an owner: an email and, when the Entra directory
picked them, an Entra object id (:mod:`external_agents`). This module matches
a signed-in person to those records and builds one read-only view of each
agent they own, for the My agents page and the weekly note.

Matching rules (nothing else matches):

* The person's **email** counts only when the sign-in proved it (the provider
  marked it verified). It is compared without regard to case with an owner
  that is itself an email address.
* The person's **object id** counts when the sign-in carried one. When both
  the owner record and the sign-in have an object id, the object id decides:
  an email address can be given to someone else, an object id cannot.
* A name, a user principal name or the opaque subject never matches.

The views only read what other modules already recorded (the enrollment
roster, drift, platform checks, the model register, waiting requests and the
access key). They run no check, call no platform and change nothing; a part
that cannot be read is reported as unreadable instead of being left out.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("maverick.agent_owners")

_EMAIL = re.compile(r"[^@\s,;<>\"'()\[\]\\]{1,64}@[^@\s,;<>\"'()\[\]\\]{1,255}\.[^@\s,;<>\"'()\[\]\\]{2,63}")
_OBJECT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
#: Spending at or above this share of the limit is reported to the owner.
SPEND_WARNING_SHARE = 0.8
#: An agent enrolled for less than this long is not reported as unheard from.
QUIET_GRACE_SECONDS = 24 * 3600

LIFECYCLE_LABELS = {"active": "Active", "suspended": "Paused", "revoked": "Access blocked",
                    "contained": "Blocked for rule breaks", "expired": "Access expired",
                    "not_yet_valid": "Not active yet", "missing_trust": "Access not set up"}
_BLOCKED = {"suspended", "revoked", "contained"}
DRIFT_LABELS = {"no_baseline": "No baseline yet", "learning": "Collecting activity",
                "within_baseline": "Matches its baseline", "drifted": "Changed since its baseline"}


class AgentOwnersError(Exception):
    """The roster of enrolled agents could not be read."""


@dataclass(frozen=True)
class Identity:
    """What a verified sign-in proves about a person, for matching owners."""

    email: str = ""
    object_id: str = ""

    def __bool__(self) -> bool:
        return bool(self.email or self.object_id)


def clean_email(value: Any) -> str:
    """The address in ``value`` in lower case, or "" when it is not exactly one
    plain email address (a name, a list or a ``Name <address>`` is not)."""
    if not isinstance(value, str):
        return ""
    text = value.strip().casefold()
    return text if len(text) <= 254 and _EMAIL.fullmatch(text) else ""


def clean_object_id(value: Any) -> str:
    """An Entra object id in lower case, or "" when it is not one."""
    text = value.strip().lower() if isinstance(value, str) else ""
    return text if _OBJECT_ID.fullmatch(text) else ""


def identity_from_claims(claims: Any, *, issuer: str = "", subject: str = "") -> Identity:
    """The identity a verified sign-in proves.

    ``claims`` are those of a verified principal: a browser session carries
    ``verified_email`` (set only when the provider marked the email verified);
    a verified ID token carries ``email`` with ``email_verified`` true and the
    Entra ``oid``; a trusted reverse proxy vouches for the identity it forwards,
    which counts as an email only when it is one. An email the provider did not
    verify, a user principal name and the subject never count."""
    claims = claims if isinstance(claims, dict) else {}
    via = claims.get("via")
    if issuer == "proxy" or via == "proxy":
        return Identity(email=clean_email(subject))
    email = ""
    if via == "session":
        email = clean_email(claims.get("verified_email"))
    elif claims.get("email_verified") is True:
        email = clean_email(claims.get("email"))
    return Identity(email=email, object_id=clean_object_id(claims.get("oid")))


def owner_email(row: dict) -> str:
    """The address an agent's owner can be written to, or ""."""
    return clean_email(row.get("owner"))


def owns(row: dict, who: Identity) -> bool:
    """Whether the person is the owner recorded on this roster row."""
    if not who:
        return False
    recorded_id = clean_object_id(row.get("owner_object_id"))
    if recorded_id and who.object_id:
        return recorded_id == who.object_id
    address = owner_email(row)
    return bool(address and who.email and address == who.email)


def _roster() -> list[dict]:
    from . import external_agents

    try:
        return external_agents.roster()
    except Exception as exc:  # noqa: BLE001 -- an unreadable roster must not look like "owns nothing"
        log.warning("agent owners: roster unreadable (%s)", type(exc).__name__)
        raise AgentOwnersError("The list of agents could not be read.") from exc


def owned_by(who: Identity, *, now: float | None = None) -> list[dict]:
    """Views of the agents this person owns, by name. Reads only."""
    mine = [row for row in _roster() if owns(row, who)]
    return _views(mine, time.time() if now is None else float(now))


def by_owner(*, now: float | None = None) -> dict[str, list[dict]]:
    """Views of every agent whose owner is an email address, grouped by that
    address. Agents with no usable owner address are left out. Reads only."""
    groups: dict[str, list[dict]] = {}
    for row in _roster():
        address = owner_email(row)
        if address:
            groups.setdefault(address, []).append(row)
    moment = time.time() if now is None else float(now)
    return {address: _views(rows, moment) for address, rows in sorted(groups.items())}


def object_id_of(address: str) -> str:
    """The object id recorded beside this owner address on any of its agents."""
    for row in _roster():
        if owner_email(row) == address and clean_object_id(row.get("owner_object_id")):
            return clean_object_id(row.get("owner_object_id"))
    return ""


# -------------------------------------------------------------------- views

def _label(value: Any, limit: int = 80) -> str:
    text = "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in str(value or ""))
    return " ".join(text.split())[:limit]


def _views(rows: list[dict], now: float) -> list[dict]:
    if not rows:
        return []
    shared = _shared()
    out = [_view(row, shared, now) for row in rows]
    return sorted(out, key=lambda v: (v["name"].casefold(), v["id"]))


def _shared() -> dict[str, Any]:
    """What every agent's view needs, read once."""
    shared: dict[str, Any] = {"approvals": None, "registry": None, "key_days": 14, "paused": None}
    try:
        from .world_model import open_world

        shared["approvals"] = [
            a for a in open_world().pending_approvals()
            if getattr(a, "provenance", None) == "external_agents"]
    except Exception as exc:  # noqa: BLE001 -- shown as unreadable
        log.warning("agent owners: waiting requests unreadable (%s)", type(exc).__name__)
    try:
        from . import agent_trust

        shared["registry"] = agent_trust.load_registry(strict=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("agent owners: access keys unreadable (%s)", type(exc).__name__)
    try:
        from .revocation import shared as revocations

        shared["paused"] = set(revocations().revoked())
    except Exception as exc:  # noqa: BLE001
        log.warning("agent owners: pauses unreadable (%s)", type(exc).__name__)
    try:
        from . import expiry_reminders

        shared["key_days"] = expiry_reminders.key_warning_days()
    except Exception:  # noqa: BLE001 -- the default window
        pass
    return shared


def _view(row: dict, shared: dict, now: float) -> dict:
    from . import outside_roster

    agent_id = str(row["id"])
    level = outside_roster.level_of(row)
    lifecycle = str(row.get("lifecycle") or "")
    contained = bool(row.get("contained"))
    paused = shared["paused"] is not None and f"agent:{agent_id}" in shared["paused"]
    drift = _drift(agent_id)
    platform = _platform(agent_id, drift)
    return {
        "id": agent_id,
        "name": _label(row.get("description") or agent_id),
        "platform_label": _label(row.get("platform_label")),
        "owner": owner_email(row),
        "level": level,
        "level_label": outside_roster.LEVEL_LABELS[level],
        "heard_at": outside_roster._heard_at(row),
        "enrolled_at": row.get("enrolled_at") if isinstance(row.get("enrolled_at"), (int, float)) else None,
        "lifecycle": lifecycle,
        "lifecycle_label": "Blocked after repeated rule breaks" if contained
        else "Paused" if paused else LIFECYCLE_LABELS.get(lifecycle, "Not available"),
        "blocked": contained or paused or lifecycle in _BLOCKED,
        "drift": drift,
        "platform": platform,
        "models": _models(agent_id),
        "spend": _spend(row),
        "waiting": _waiting(agent_id, shared),
        "key": _key(agent_id, shared, now),
    }


def _drift(agent_id: str) -> dict:
    try:
        from . import agent_drift

        result = agent_drift.evaluate(agent_id)
    except Exception as exc:  # noqa: BLE001 -- reported as unreadable
        log.warning("agent owners: drift unreadable (%s)", type(exc).__name__)
        return {"readable": False, "state": "", "state_label": "Could not be read", "open": 0,
                "changed_on_platform": 0, "highest_severity": ""}
    open_findings = [f for f in result.get("findings") or [] if not f.get("acknowledged")]
    on_platform = [f for f in open_findings if f.get("kind") == "config_changed" and f.get("source") == "discovery"]
    state = str(result.get("state") or "")
    return {"readable": True, "state": state, "state_label": DRIFT_LABELS.get(state, "Not available"),
            "open": len(open_findings), "changed_on_platform": len(on_platform),
            "highest_severity": max((str(f.get("severity") or "") for f in open_findings),
                                    key=lambda s: {"high": 3, "medium": 2, "low": 1}.get(s, 0), default="")}


def _platform(agent_id: str, drift: dict) -> dict:
    """The platform check's last word on the agent. Reads the saved record only."""
    out = {"readable": True, "linked": False, "watched": False, "checked": False, "missing": False,
           "last_checked_at": None, "changed": bool(drift.get("changed_on_platform")), "label": ""}
    try:
        from . import agent_watch

        view = agent_watch.platform_view(agent_id)
    except Exception as exc:  # noqa: BLE001
        log.warning("agent owners: platform check unreadable (%s)", type(exc).__name__)
        return {**out, "readable": False, "label": "Could not be read"}
    if view is None:
        return {**out, "label": "Not linked to a record on its platform"}
    out.update(linked=True, watched=bool(view["watched"]), checked=bool(view["checked"]),
               missing=bool(view["missing_on_platform"]), last_checked_at=view["last_checked_at"])
    if not view["watched"]:
        out["label"] = "Its platform is not being checked"
    elif view["missing_on_platform"]:
        out["label"] = "No longer found on its platform"
    elif not view["checked"]:
        out["label"] = "Not checked yet"
    elif out["changed"]:
        out["label"] = "Changed on its platform"
    else:
        out["label"] = "Found on its platform"
    return out


def _models(agent_id: str) -> dict:
    try:
        from . import model_register

        found = model_register.findings_for_agent(agent_id)
    except Exception as exc:  # noqa: BLE001
        log.warning("agent owners: model register unreadable (%s)", type(exc).__name__)
        return {"readable": False, "open": 0, "names": []}
    return {"readable": True, "open": len(found),
            "names": sorted({_label(f.get("model"), 60) for f in found if f.get("model")})}


def _spend(row: dict) -> dict:
    limit = row.get("max_dollars")
    limit = float(limit) if isinstance(limit, (int, float)) and not isinstance(limit, bool) and limit > 0 else None
    spent = float(row.get("period_spent") or 0.0)
    return {"spent": spent, "limit": limit,
            "period": "this month" if row.get("period") == "monthly" else "in total",
            "share": (spent / limit) if limit else None,
            "near_limit": bool(limit and spent / limit >= SPEND_WARNING_SHARE)}


def _waiting(agent_id: str, shared: dict) -> dict:
    approvals = shared["approvals"]
    if approvals is None:
        return {"readable": False, "count": 0}
    return {"readable": True,
            "count": sum(1 for a in approvals if getattr(a, "requested_by", None) == f"agent:{agent_id}")}


def _key(agent_id: str, shared: dict, now: float) -> dict:
    registry = shared["registry"]
    if registry is None:
        return {"readable": False, "state": "", "label": "Could not be read", "expires_at": None}
    entry = registry.get(agent_id)
    end = getattr(entry, "expires_at", None)
    if entry is None or getattr(entry, "revoked", False):
        return {"readable": True, "state": "none", "label": "No working access key", "expires_at": None}
    if end is None:
        return {"readable": True, "state": "active", "label": "Does not expire", "expires_at": None}
    days = shared["key_days"]
    if now >= end:
        state = "ended"
    elif days and end - now <= days * 86400:
        state = "ending"
    else:
        state = "active"
    return {"readable": True, "state": state, "label": "", "expires_at": float(end)}


def attention(view: dict, now: float | None = None) -> list[str]:
    """The kinds of thing about this agent that need its owner, in a fixed
    order: ``platform``, ``drift``, ``models``, ``blocked``, ``spend``, ``key``,
    ``requests``, ``silent``. Unreadable parts are not guessed at."""
    moment = time.time() if now is None else float(now)
    kinds = []
    if view["platform"]["missing"] or view["drift"]["changed_on_platform"]:
        kinds.append("platform")
    if view["drift"]["open"] - view["drift"]["changed_on_platform"] > 0:
        kinds.append("drift")
    if view["models"]["open"]:
        kinds.append("models")
    if view["blocked"]:
        kinds.append("blocked")
    if view["spend"]["near_limit"]:
        kinds.append("spend")
    if view["key"]["state"] in ("ending", "ended"):
        kinds.append("key")
    if view["waiting"]["count"]:
        kinds.append("requests")
    enrolled = view["enrolled_at"]
    if view["level"] == "added" and (enrolled is None or moment - enrolled >= QUIET_GRACE_SECONDS):
        kinds.append("silent")
    return kinds


__all__ = [
    "AgentOwnersError",
    "Identity",
    "attention",
    "by_owner",
    "clean_email",
    "clean_object_id",
    "identity_from_claims",
    "object_id_of",
    "owned_by",
    "owner_email",
    "owns",
]
