"""The register of models in use, with a baseline and checks for each.

Second Shift cannot see inside the platform where a model runs, but it learns
which models agents use: from the ``model`` an agent declares in its run
reports, from the model a platform check finds in an agent's description, and
from people who enter a model by hand. This module keeps that register and the
statistical drift of each model:

* ``sync`` -- adds the models enrolled agents are seen to use and keeps each
  model's list of agents, first seen and last seen up to date.
* ``add`` / ``edit`` -- a person enters or describes a model: name, provider,
  purpose, owner, risk tier and the agents that use it.
* ``receive_samples`` -- the owner sends a batch. A ``baseline`` batch becomes
  a candidate profile; ``approve_baseline`` makes it the baseline (a named
  person, audited). A ``check`` batch is compared with the approved baseline
  (``model_drift.compare``) and its result and findings are kept.
* ``acknowledge`` and the read models (``list_models``, ``get``,
  ``findings_for_agent``, ``home_items``).

A finding is audited (``model_drift_detected``) and alerted once for as long as
it lasts; an acknowledgement covers it at the severity it had. Nothing here
contains an agent or changes what a model may do: a statistic cannot tell that
a model is wrong, so a person decides.

What it does not store. A batch is evaluated in memory and dropped. Only the
aggregate profile (bin edges and counts, category counts, means, an embedding
centroid, an accuracy) and each check's statistics are kept, in the governed
record store (private files on one server, PostgreSQL when the deployment uses
it). A failure writing the audit log stops the change it would describe.
"""
from __future__ import annotations

import copy
import hashlib
import logging
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from . import model_drift
from .governed_records import GovernedRecordCapacityError, GovernedRecordStore
from .privacy_ops import RecordConflict

log = logging.getLogger("maverick.model_register")

STORE = GovernedRecordStore("model_register", "MDL", "model_register", archive_when_full=False)

RISK_TIERS = ("unrated", "low", "medium", "high")
#: What each monitoring status is called to a person.
STATUS_LABELS = {
    "not_monitored": "No baseline yet",
    "awaiting_approval": "Baseline waiting for approval",
    "monitored": "Monitored",
    "drifting": "Changed from its baseline",
}
_RANK = {"low": 1, "medium": 2, "high": 3}
_ALERT_SEVERITY = {"low": "info", "medium": "warning", "high": "high"}

_MAX_MODELS = 500
_MAX_CHECKS = 30
_MAX_FINDINGS = 100
_MAX_AGENTS = 200
_QUIET_SECONDS = 24 * 3600
_SEEN_REFRESH_SECONDS = 3600
_NAME = re.compile(r"\w[\w .:/@+\-]{0,119}")
_AGENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@\-]{0,63}")
_VIA = {"declared": "run report", "platform": "platform check", "hand": "entered by hand"}


class ModelRegisterError(Exception):
    """A refusal an operator can act on (bad input, no baseline, too little data)."""


class ModelNotFound(ModelRegisterError):
    """No such model."""


class ModelConflict(ModelRegisterError):
    """The model already exists, or the request is out of step with its state."""


class ModelStoreError(ModelRegisterError):
    """The register cannot be read or written, so nothing was changed."""


_NOT_RECORDED = ("This could not be written to the audit log, so nothing was changed. "
                 "Try again; if it keeps failing, check where the audit log is stored.")
_UNAVAILABLE = ("The model register cannot be read or written right now, so nothing was changed. "
                "Ask an administrator to check the server's data folder and the server log.")


def model_id(name: str) -> str:
    """The stable id of a model: one per name, however its letters are cased."""
    key = " ".join(str(name).casefold().split())
    return "MDL-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


# ------------------------------------------------------------------ cleaning

def _looks_secret(text: str) -> bool:
    try:
        from .safety.secret_detector import redact
        return redact(text)[0] != text
    except Exception:
        return True


def _text(value: Any, what: str, limit: int, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ModelRegisterError(f"{what} must be text.")
    text = " ".join(value.split())
    if required and not text:
        raise ModelRegisterError(f"{what} is needed.")
    if len(text) > limit or not text.isprintable():
        raise ModelRegisterError(f"{what} must be plain text of at most {limit} characters.")
    if text and _looks_secret(text):
        raise ModelRegisterError(f"{what} looks like a password or key, so it was not saved.")
    return text


def _model_name(value: Any) -> str:
    text = _text(value, "The model name", 120, required=True)
    if not _NAME.fullmatch(text):
        raise ModelRegisterError("The model name may hold letters, digits, spaces and . : / @ + - only.")
    return text


def _agent_label(value: Any) -> str:
    """A model name seen on an agent, or "" when it is not a plain name (a
    digest or text that does not look like a name is not registered)."""
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if not text or text.startswith("sha256:") or not _NAME.fullmatch(text) or _looks_secret(text):
        return ""
    return text


def _enrolled_ids() -> set[str]:
    try:
        from . import external_agents
        return {str(agent["id"]) for agent in external_agents.roster()}
    except Exception as exc:
        raise ModelStoreError("The list of agents could not be read, so the agents were not checked.") from exc


def _hand_agents(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_AGENTS:
        raise ModelRegisterError(f"Agents must be a list of at most {_MAX_AGENTS} agent ids.")
    ids = []
    for item in value:
        if not isinstance(item, str) or not _AGENT_ID.fullmatch(item.strip()):
            raise ModelRegisterError("Each agent must be the id of an agent added to Second Shift.")
        if item.strip() not in ids:
            ids.append(item.strip())
    if ids:
        unknown = [a for a in ids if a not in _enrolled_ids()]
        if unknown:
            raise ModelRegisterError(f"{unknown[0]} is not an agent added to Second Shift.")
    return ids


def _fields(source: Mapping[str, Any], *, names: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "provider" in names and "provider" in source:
        out["provider"] = _text(source["provider"], "The provider", 80)
    if "purpose" in names and "purpose" in source:
        out["purpose"] = _text(source["purpose"], "The purpose", 300)
    if "owner" in names and "owner" in source:
        out["owner"] = _text(source["owner"], "The owner", 120)
    if "risk_tier" in names and "risk_tier" in source:
        tier = source["risk_tier"]
        if tier not in RISK_TIERS:
            raise ModelRegisterError("The risk tier is one of: " + ", ".join(RISK_TIERS) + ".")
        out["risk_tier"] = tier
    if "agents" in names and "agents" in source:
        out["hand_agents"] = _hand_agents(source["agents"])
    return out


# ------------------------------------------------------------------- storage

def _guard(work: Callable[[], Any]) -> Any:
    from .governed_records import GovernedRecordBackendError
    from .privacy_ops import PrivacyStateError
    try:
        return work()
    except (GovernedRecordBackendError, PrivacyStateError, OSError) as exc:
        if isinstance(exc, GovernedRecordCapacityError):
            raise ModelRegisterError(
                f"The register is full ({_MAX_MODELS} models). Ask an administrator to make room.") from exc
        log.warning("model register unavailable", exc_info=True)
        raise ModelStoreError(_UNAVAILABLE) from exc


def _records() -> list[dict]:
    return [row for row in _guard(lambda: STORE.list(limit=_MAX_MODELS + 1)) if isinstance(row, dict)]


def _load(model: str) -> dict:
    found = _guard(lambda: STORE.get(model)) if re.fullmatch(r"MDL-[0-9a-f]{20}", str(model)) else None
    if not isinstance(found, dict):
        raise ModelNotFound("There is no such model in the register.")
    return found


def _modify(model: str, mutate: Callable[[dict], None], *, action: str, actor: str) -> dict:
    """One compare-and-swap change, retried when another change got in first."""
    for _ in range(5):
        revision = int(_load(model)["revision"])
        try:
            saved = _guard(lambda rev=revision: STORE.update(model, mutate, expected_revision=rev,
                                                             action=action, actor=actor))
        except RecordConflict:
            continue
        if saved is None:
            raise ModelNotFound("There is no such model in the register.")
        return saved
    raise ModelConflict("The model was changed by someone else at the same moment. Try again.")


def _blank(name: str, now: float, *, hand: bool) -> dict:
    return {"id": model_id(name), "name": name, "provider": "", "purpose": "", "owner": "",
            "risk_tier": "unrated", "hand_entered": hand, "hand_agents": [], "agents": {},
            "first_seen": now, "last_seen": now, "candidate": None, "baseline": None,
            "checks": [], "findings": [], "reported": {}, "acknowledged": {}}


def _audit(kind: str, record: Mapping[str, Any], **payload: Any) -> bool:
    """One audit row. A refusal propagates, so the change it describes is not
    made without its evidence."""
    from .audit import audit_event
    return audit_event(kind, agent="model_register", model_id=record["id"], model=record["name"], **payload)


# ---------------------------------------------------------------------- sync

def _seen_models() -> tuple[dict[str, dict[str, dict]], list[str]]:
    """Model name -> agent id -> ``{via, first, last}`` as agents report them
    now, and the problems met reading them."""
    from . import agent_drift

    seen: dict[str, dict[str, dict]] = {}
    problems: list[str] = []
    try:
        agents = sorted(_enrolled_ids())
    except ModelStoreError as exc:
        return seen, [str(exc)]
    for agent_id in agents:
        try:
            config = agent_drift.detail(agent_id).get("config") or {}
        except Exception:
            log.warning("model register: could not read %r", agent_id, exc_info=True)
            problems.append("Some agents' records could not be read, so their models may be missing.")
            break
        found = []
        declared = config.get("declared") or {}
        found.append(("declared", declared.get("model"), declared.get("seen_at")))
        discovered = config.get("discovered") or {}
        fields = ((discovered.get("description") or {}).get("fields")) or {}
        found.append(("platform", fields.get("model"), discovered.get("seen_at")))
        for via, raw, at in found:
            name = _agent_label(raw)
            if not name:
                continue
            moment = float(at) if isinstance(at, (int, float)) and not isinstance(at, bool) else 0.0
            entry = seen.setdefault(name, {}).setdefault(agent_id, {"via": [], "first": moment, "last": moment})
            entry["via"].append(via)
            entry["first"] = min(entry["first"], moment) if entry["first"] and moment else (entry["first"] or moment)
            entry["last"] = max(entry["last"], moment)
    return seen, problems


def _merge_agents(row: dict, observed: Mapping[str, dict], now: float) -> bool:
    """Bring a record's agents up to date with what agents report. ``True``
    when something a person would notice changed."""
    changed = False
    agents = row["agents"]
    for agent_id, entry in agents.items():
        if entry.get("current") and agent_id not in observed:
            entry["current"] = False
            changed = True
    for agent_id, entry in observed.items():
        before = agents.get(agent_id) or {}
        first = before.get("first_seen") or entry["first"] or now
        last = max(float(before.get("last_seen") or 0), entry["last"] or now)
        after = {"via": sorted(set(entry["via"])), "first_seen": first, "last_seen": last, "current": True}
        if (before.get("current") is not True or before.get("via") != after["via"]
                or last - float(before.get("last_seen") or 0) >= _SEEN_REFRESH_SECONDS):
            agents[agent_id] = after
            changed = True
    if len(agents) > _MAX_AGENTS:
        keep = sorted(agents.items(), key=lambda item: float(item[1].get("last_seen") or 0), reverse=True)
        row["agents"] = dict(keep[:_MAX_AGENTS])
        changed = True
    if changed:
        firsts = [float(e["first_seen"]) for e in row["agents"].values() if e.get("first_seen")]
        lasts = [float(e["last_seen"]) for e in row["agents"].values() if e.get("last_seen")]
        if row.get("hand_entered"):
            firsts.append(float(row["first_seen"]))
            lasts.append(float(row["last_seen"]))
        row["first_seen"], row["last_seen"] = min(firsts, default=now), max(lasts, default=now)
    return changed


def sync(*, now: float | None = None) -> dict:
    """Add the models agents are seen to use and refresh each model's agents.
    Returns ``{"added", "updated", "problems"}``; problems are plain
    sentences about what could not be read. Writes only what changed."""
    moment = time.time() if now is None else float(now)
    seen, problems = _seen_models()
    by_id = {row["id"]: row for row in _records()}
    added = updated = 0
    for name, observed in seen.items():
        mid = model_id(name)
        row = by_id.get(mid)
        if row is None:
            if len(by_id) >= _MAX_MODELS:
                problems.append(f"The register is full ({_MAX_MODELS} models), so some models were not added.")
                break
            record = _blank(name, moment, hand=False)
            _merge_agents(record, observed, moment)
            try:
                by_id[mid] = _guard(lambda r=record: STORE.create(r, action="model_seen", actor="system",
                                                                  max_records=_MAX_MODELS))
                added += 1
                continue
            except RecordConflict:
                row = _load(mid)  # another request added it first
        updated += _refresh_agents(mid, row, observed, moment)
    reported = {model_id(name) for name in seen}
    for mid, row in by_id.items():
        if mid not in reported and any(e.get("current") for e in row["agents"].values()):
            updated += _refresh_agents(mid, row, {}, moment)
    return {"added": added, "updated": updated, "problems": sorted(set(problems))}


def _refresh_agents(mid: str, row: Mapping[str, Any], observed: Mapping[str, dict], moment: float) -> int:
    """Write a model's agents when they changed. ``1`` when written."""
    if not _merge_agents(copy.deepcopy(dict(row)), observed, moment):
        return 0
    _modify(mid, lambda r: _merge_agents(r, observed, moment), action="model_seen", actor="system")
    return 1


# ------------------------------------------------------------- hand entries

def add(name: Any, *, actor: str, now: float | None = None, **fields: Any) -> dict:
    """Enter a model by hand. ``fields`` may hold ``provider``, ``purpose``,
    ``owner``, ``risk_tier`` and ``agents``. Raises :class:`ModelConflict` when
    the name is already in the register."""
    clean = _model_name(name)
    values = _fields(fields, names=("provider", "purpose", "owner", "risk_tier", "agents"))
    moment = time.time() if now is None else float(now)
    record = {**_blank(clean, moment, hand=True), **values}
    if _guard(lambda: STORE.get(record["id"])) is not None:
        raise ModelConflict(f"{clean} is already in the register. Open it to change it.")
    if not _audit("model_registered", record, actor=actor, risk_tier=record["risk_tier"]):
        raise ModelRegisterError(_NOT_RECORDED)
    try:
        saved = _guard(lambda: STORE.create(record, action="model_registered", actor=actor,
                                            max_records=_MAX_MODELS))
    except RecordConflict as exc:
        raise ModelConflict(f"{clean} is already in the register. Open it to change it.") from exc
    return view(saved)


def edit(model: str, *, actor: str, **fields: Any) -> dict:
    """Change what people say about a model. Its name never changes. A model
    Second Shift found on its own can have its provider, purpose, owner and
    risk tier described, but its agents come from what they report."""
    record = _load(model)
    names = ("provider", "purpose", "owner", "risk_tier") + (("agents",) if record.get("hand_entered") else ())
    if set(fields) - set(names) - {"name"}:
        raise ModelRegisterError("The agents of a model that Second Shift found come from what the agents report; "
                                 "only the provider, purpose, owner and risk tier can be changed.")
    if "name" in fields and fields["name"] != record["name"]:
        raise ModelRegisterError("A model's name cannot be changed. Enter the new name as another model.")
    values = _fields(fields, names=names)
    if not values:
        return view(record)
    if not _audit("model_edited", record, actor=actor, changed=sorted(values)):
        raise ModelRegisterError(_NOT_RECORDED)
    return view(_modify(model, lambda row: row.update(values), action="model_edited", actor=actor))


# ------------------------------------------------------------------- samples

def _profile_view(approved: Mapping[str, Any] | None) -> dict | None:
    """A baseline or candidate as shown: who and when, and per signal its
    kind, size and summary. The bin edges and counts are included; they are
    the profile and hold no sample."""
    if not isinstance(approved, Mapping):
        return None
    profile = approved.get("profile") or {}
    rows = []
    for name, signal in (profile.get("signals") or {}).items():
        row = {"signal": name, "kind": signal.get("kind"), "n": signal.get("n")}
        if signal.get("kind") == "numeric":
            row.update(mean=signal["mean"], low=signal["edges"][0], high=signal["edges"][-1], counts=signal["counts"])
        elif signal.get("kind") == "categorical":
            row.update(categories=signal["categories"], counts=signal["counts"])
        elif signal.get("kind") == "embedding":
            row.update(dimension=signal["dimension"])
        elif signal.get("kind") == "accuracy":
            row.update(value=signal["value"])
        rows.append(row)
    return {"received_by": approved.get("received_by", ""), "received_at": approved.get("received_at"),
            "approved_by": approved.get("approved_by", ""), "approved_at": approved.get("approved_at"),
            "signals": rows}


def receive_samples(model: str, samples: Mapping[str, Any], *, purpose: str, by: str,
                    now: float | None = None) -> dict:
    """Evaluate one batch in memory and keep only its aggregates.

    ``purpose`` ``"baseline"`` makes a candidate profile that waits for
    :func:`approve_baseline`. ``"check"`` compares the batch with the approved
    baseline, keeps the statistics and reports findings not reported before
    (audited, and one alert for the batch). Raises
    :class:`~maverick.model_drift.SampleError` for a batch that cannot be used
    and :class:`ModelRegisterError` when there is no approved baseline."""
    cfg = model_drift.settings()
    if not cfg["enable"]:
        raise ModelConflict("Model drift checks are turned off in this installation.")
    if purpose not in ("baseline", "check"):
        raise ModelRegisterError("A batch is for a baseline or for a check.")
    moment = time.time() if now is None else float(now)
    record = _load(model)
    if purpose == "baseline":
        profile = model_drift.build_profile(samples, bins=cfg["bins"], min_samples=cfg["min_samples"])
        candidate = {"profile": profile, "received_by": by, "received_at": moment}
        if not _audit("model_baseline_received", record, actor=by,
                      signals=sorted(profile["signals"]), samples=max(s["n"] for s in profile["signals"].values())):
            raise ModelRegisterError(_NOT_RECORDED)
        saved = _modify(model, lambda row: row.update(candidate=candidate), action="model_baseline_received",
                        actor=by)
        return {"purpose": "baseline", "accepted": True, "awaiting_approval": True,
                "candidate": _profile_view(saved["candidate"])}
    approved = record.get("baseline")
    if not approved:
        raise ModelConflict("This model has no approved baseline yet. Send a baseline batch and ask an "
                            "administrator to approve it first.")
    result = model_drift.compare(approved["profile"], samples, cfg)
    outcome = _record_check(model, result, by=by, moment=moment)
    return {"purpose": "check", "compared": result["compared"], "skipped": result["skipped"],
            "findings": outcome["findings"], "new_findings": outcome["new"]}


def _slim(signals: Mapping[str, Mapping]) -> dict:
    out = {}
    for name, stats in signals.items():
        row: dict[str, Any] = {"n": stats["n"]}
        for key in ("psi", "js", "cosine_distance", "value", "decay"):
            if key in stats:
                row[key] = round(stats[key], 6)
        for key in ("chi2", "ks"):
            if key in stats:
                row[f"{key}_p"] = round(stats[key]["p_value"], 6)
        out[name] = row
    return out


def _record_check(model: str, result: Mapping[str, Any], *, by: str, moment: float) -> dict:
    findings = result["findings"]
    psis = [s["psi"] for s in result["signals"].values() if "psi" in s]
    check = {"at": moment, "by": by, "signals": _slim(result["signals"]), "skipped": result["skipped"],
             "max_psi": round(max(psis), 6) if psis else None, "findings": [f["key"] for f in findings]}
    recorded: list[dict] = []

    def mutate(row: dict) -> None:
        recorded.clear()
        reported = row["reported"]
        acked = row["acknowledged"]
        for finding in findings:
            ack = acked.get(finding["key"]) or {}
            finding["acknowledged"] = bool(ack) and _RANK[finding["severity"]] <= _RANK.get(ack.get("severity"), 0)
            if finding["acknowledged"]:
                finding["acknowledged_by"], finding["acknowledged_at"] = ack.get("by", ""), ack.get("at")
        for finding in findings:
            seen = reported.get(finding["key"]) or {}
            if finding["acknowledged"] or _RANK[finding["severity"]] <= _RANK.get(seen.get("severity"), 0):
                continue
            if _audit("model_drift_detected", row, finding=finding["key"], finding_kind=finding["kind"],
                      signal=finding["signal"], severity=finding["severity"], value=finding["value"],
                      threshold=finding["threshold"], summary=finding["summary"]):
                reported[finding["key"]] = {"at": moment, "seen": moment, "severity": finding["severity"]}
                recorded.append(finding)
        for finding in findings:
            entry = reported.get(finding["key"])
            if entry and moment - float(entry.get("seen") or 0) >= _SEEN_REFRESH_SECONDS:
                entry["seen"] = moment
            if finding["key"] in reported:
                finding["reported_at"] = reported[finding["key"]].get("at")
        present = {f["key"] for f in findings}
        for book in (reported, acked):
            for key in [k for k, e in book.items() if k not in present
                        and moment - float((e or {}).get("seen") or (e or {}).get("at") or 0) > _QUIET_SECONDS]:
                del book[key]
            for key, entry in book.items():
                if key in present and moment - float(entry.get("seen") or 0) >= _SEEN_REFRESH_SECONDS:
                    entry["seen"] = moment
        row["findings"] = findings[:_MAX_FINDINGS]
        row["checks"] = [*row["checks"], check][-_MAX_CHECKS:]
        row["last_check_at"] = moment

    saved = _modify(model, mutate, action="model_checked", actor=by)
    if recorded:
        _alert(saved, recorded)
    return {"findings": [_finding_view(f) for f in saved["findings"]], "new": [f["key"] for f in recorded]}


def _alert(record: Mapping[str, Any], new: list[dict]) -> None:
    """One operator alert for the findings a check reported for the first time."""
    worst = max(new, key=lambda f: _RANK[f["severity"]])
    text = f"The data around the model {record['name']} has moved away from its baseline. {worst['summary']}"
    if len(new) > 1:
        more = len(new) - 1
        text += f" {more} more {'finding needs' if more == 1 else 'findings need'} review."
    try:
        from .ops_alert import alert
        alert("model_drift.detected", text, severity=_ALERT_SEVERITY[worst["severity"]])
    except Exception:  # pragma: no cover -- notification never blocks
        log.warning("model register: alert delivery failed", exc_info=True)


def approve_baseline(model: str, *, actor: str, now: float | None = None) -> dict:
    """Make the waiting candidate the model's baseline. Whoever approves is
    recorded, and findings and acknowledgements of the old baseline end."""
    moment = time.time() if now is None else float(now)
    record = _load(model)
    candidate = record.get("candidate")
    if not candidate:
        raise ModelConflict("There is no baseline batch waiting. Send one first.")
    if not _audit("model_baseline_approved", record, actor=actor, approved_by=actor,
                  signals=sorted(candidate["profile"]["signals"]),
                  received_by=candidate.get("received_by", "")):
        raise ModelRegisterError(_NOT_RECORDED)

    def mutate(row: dict) -> None:
        waiting = row.get("candidate")
        if not waiting or waiting != candidate:
            raise ModelConflict("A newer baseline batch arrived while you were approving. Look at it and approve again.")
        row["baseline"] = {**waiting, "approved_by": actor, "approved_at": moment}
        row.update(candidate=None, findings=[], reported={}, acknowledged={})

    return view(_modify(model, mutate, action="model_baseline_approved", actor=actor))


def acknowledge(model: str, finding_key: str, *, actor: str, now: float | None = None) -> dict:
    """Dismiss one open finding. It stays listed, marked acknowledged, until a
    later check no longer shows it for a day or a new baseline is approved; a
    finding that gets more severe is open again."""
    moment = time.time() if now is None else float(now)
    record = _load(model)
    finding = next((f for f in record["findings"] if f["key"] == finding_key and not f.get("acknowledged")), None)
    if finding is None:
        raise ModelNotFound(f"{record['name']} has no open finding {finding_key!r} to acknowledge.")
    if not _audit("model_drift_acknowledged", record, actor=actor, acknowledged_by=actor,
                  finding=finding["key"], finding_kind=finding["kind"], severity=finding["severity"]):
        raise ModelRegisterError(_NOT_RECORDED)

    def mutate(row: dict) -> None:
        for item in row["findings"]:
            if item["key"] == finding_key:
                item.update(acknowledged=True, acknowledged_by=actor, acknowledged_at=moment)
        row["acknowledged"][finding_key] = {"by": actor, "at": moment, "seen": moment,
                                            "severity": finding["severity"]}

    _modify(model, mutate, action="model_acknowledged", actor=actor)
    return {"model_id": model, "finding": finding_key, "acknowledged_by": actor, "acknowledged_at": moment}


# --------------------------------------------------------------------- views

def _finding_view(finding: Mapping[str, Any]) -> dict:
    out = {k: finding.get(k) for k in ("key", "signal", "kind", "severity", "summary", "value", "threshold")}
    out["acknowledged"] = bool(finding.get("acknowledged"))
    for key in ("acknowledged_by", "acknowledged_at", "reported_at"):
        if finding.get(key) is not None:
            out[key] = finding[key]
    return out


def _open(record: Mapping[str, Any]) -> list[dict]:
    return [f for f in record.get("findings") or () if not f.get("acknowledged")]


def status_of(record: Mapping[str, Any]) -> str:
    if record.get("baseline"):
        return "drifting" if _open(record) else "monitored"
    return "awaiting_approval" if record.get("candidate") else "not_monitored"


def _agents_of(record: Mapping[str, Any]) -> list[dict]:
    rows = [{"id": agent_id, "current": bool(entry.get("current")),
             "via": [_VIA.get(v, v) for v in entry.get("via") or ()], "last_seen": entry.get("last_seen")}
            for agent_id, entry in (record.get("agents") or {}).items()]
    listed = {row["id"] for row in rows}
    rows.extend({"id": a, "current": True, "via": [_VIA["hand"]], "last_seen": None}
                for a in record.get("hand_agents") or () if a not in listed)
    return sorted(rows, key=lambda row: (not row["current"], row["id"]))


def view(record: Mapping[str, Any]) -> dict:
    """A model as the API and the pages show it. Reads only."""
    open_findings = _open(record)
    status = status_of(record)
    checks = record.get("checks") or []
    return {
        "id": record["id"], "name": record["name"], "provider": record.get("provider", ""),
        "purpose": record.get("purpose", ""), "owner": record.get("owner", ""),
        "risk_tier": record.get("risk_tier", "unrated"), "hand_entered": bool(record.get("hand_entered")),
        "agents": _agents_of(record), "first_seen": record.get("first_seen"), "last_seen": record.get("last_seen"),
        "status": status, "status_label": STATUS_LABELS[status],
        "last_check_at": record.get("last_check_at"), "checks_count": len(checks),
        "open_findings": len(open_findings),
        "highest_severity": max((f["severity"] for f in open_findings), key=lambda s: _RANK[s], default=""),
    }


def get(model: str) -> dict:
    """One model with its baseline, waiting candidate, recent checks and
    findings. Raises :class:`ModelNotFound`."""
    record = _load(model)
    out = view(record)
    out.update(
        baseline=_profile_view(record.get("baseline")), candidate=_profile_view(record.get("candidate")),
        findings=[_finding_view(f) for f in record.get("findings") or ()],
        checks=[{"at": c["at"], "by": c["by"], "signals": c["signals"], "skipped": c.get("skipped", []),
                 "max_psi": c.get("max_psi"), "findings": c.get("findings", [])}
                for c in reversed(record.get("checks") or ())],
        settings={k: v for k, v in model_drift.settings().items()},
    )
    return out


def list_models() -> list[dict]:
    """Every model in the register, those with open findings first."""
    rows = [view(r) for r in _records()]
    return sorted(rows, key=lambda r: (-_RANK.get(r["highest_severity"], 0), r["name"].casefold()))


def agents_using(model: str, *, refresh: bool = False) -> set[str]:
    """The ids of the agents that use the model now (reported or entered by hand)."""
    if refresh:
        sync()
    record = _load(model)
    return {a["id"] for a in _agents_of(record) if a["current"]}


def models_for_agent(agent_id: str) -> list[dict]:
    """The models an agent uses now, for its own listing."""
    return [view(r) for r in _records() if agent_id in {a["id"] for a in _agents_of(r) if a["current"]}]


def findings_for_agent(agent_id: str) -> list[dict]:
    """Open findings on the models an agent uses, for the agent's page."""
    out = []
    for record in _records():
        if agent_id not in {a["id"] for a in _agents_of(record) if a["current"]}:
            continue
        out.extend({**_finding_view(f), "model_id": record["id"], "model": record["name"]} for f in _open(record))
    return sorted(out, key=lambda f: -_RANK.get(f["severity"], 0))


def home_items() -> tuple[list[dict], int]:
    """Open findings for the home page: ``(items, count)``. Reads only."""
    items, count = [], 0
    for record in _records():
        for finding in _open(record):
            count += 1
            items.append({"text": f"{record['name']}: {finding['summary']}"[:300],
                          "detail": "The data around this model differs from the baseline you approved.",
                          "href": f"/models/{record['id']}#model-findings",
                          "severity": finding["severity"] if finding["severity"] in _RANK else "medium",
                          "at": float(finding.get("reported_at") or record.get("last_check_at") or 0)})
    return items, count


__all__ = [
    "ModelConflict", "ModelNotFound", "ModelRegisterError", "ModelStoreError", "RISK_TIERS", "STATUS_LABELS",
    "acknowledge", "add", "agents_using", "approve_baseline", "edit", "findings_for_agent", "get",
    "home_items", "list_models", "model_id", "models_for_agent", "receive_samples", "status_of", "sync", "view",
]
