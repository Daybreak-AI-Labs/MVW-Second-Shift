"""Drift detection for enrolled outside agents.

An agent that runs on another platform can change without telling anyone: a
tool is wired in, its instructions are edited, the model behind it is swapped.
Second Shift cannot look inside that platform, but it does see what the agent
asks to do and what it reports back. This module keeps a small rolling record
of that activity for each enrolled agent, lets an operator approve a baseline,
and reports when the agent moves off it:

* ``observe_screen`` / ``observe_run`` / ``observe_discovered`` -- hooks the
  gateway and the discovery connectors call. They add to per-agent, per-UTC-day
  totals and remember the latest configuration fingerprint.
* ``approve_baseline`` / ``baseline`` -- a named person approves the last N
  days of totals, with the fingerprints seen so far, as what "normal" means.
* ``evaluate`` -- compares a recent window with that baseline and returns
  findings (a new tool, a shifted tool mix, changed volume or cost, more
  refusals or failures, a changed configuration), each with a severity and a
  plain-language summary.
* ``check`` / ``check_all`` / ``acknowledge`` -- the reaction: a finding is
  audited and alerted once, an operator can acknowledge it, and the agent is
  contained only when ``[agent_drift] on_drift = "contain"`` and the finding
  is high severity.
* ``roster_view`` / ``detail`` -- read models for a UI.

What it does not do. It stores totals, tool names and configuration
fingerprints, never prompts, outputs or tool arguments. It does not decide
whether an action is allowed (``external_agents.screen`` does) and a failure
here cannot change that decision: the hooks never raise. It does not judge
whether a change is good or bad, only that the agent no longer matches what a
person approved. It sees only what passes through Second Shift, so an agent
that stops reporting looks quiet, not safe.

The record is one JSON document kept with the other records
(``maverick.record_documents``), next to the enrollment sidecar, written
atomically under a cross-process lock and bounded in every direction. A file
that cannot be read is never replaced: the hooks record nothing and every
other entry point raises :class:`AgentDriftStoreError`.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import agent_watch_changes

log = logging.getLogger("maverick.agent_drift")

SCHEMA_VERSION = 1

LOW, MEDIUM, HIGH = "low", "medium", "high"
_RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}
#: Finding severity -> the severity word ``ops_alert.alert`` understands.
_ALERT_SEVERITY = {LOW: "info", MEDIUM: "warning", HIGH: "high"}

#: Storage bounds. Agents follow enrollment (same structural ceiling as the
#: sidecar); each agent keeps its newest days and a capped tool vocabulary,
#: with further tool names folded into one "(other)" entry.
_MAX_AGENTS = 500
_MAX_DAYS = 35
_MAX_TOOLS = 50
_MAX_TOOLS_PER_RUN = 200
_MAX_REPORTED = 100
_MAX_ACKNOWLEDGED = 100
_MAX_COUNT = 10 ** 12
_MAX_BASELINE_DAYS = 30
_MAX_WINDOW_DAYS = 7
#: Days of history ``detail`` returns for charts.
_SERIES_DAYS = 30

_DAY_SECONDS = 86400
#: Per-run costs below this are treated as equal (rounding dust is not drift).
_COST_FLOOR = 0.01
#: A reported finding that has not been seen for this long is forgotten, so
#: the same finding coming back later is reported again.
_QUIET_SECONDS = 24 * 3600
#: How often a still-present finding's "last seen" stamp is refreshed.
_SEEN_REFRESH_SECONDS = 3600

_OTHER_TOOL = "(other)"
#: Prefix of the digest a tool is counted under when its name cannot be shown.
_UNNAMED = "unnamed:"
#: How far the share of uncounted "(other)" tool use may rise above the
#: baseline's before it is treated as new tools.
_OTHER_RISE = 0.05
_LABEL = re.compile(r"\w[\w .:/@+\-]*")
_COUNTERS = ("runs", "failures", "tool_calls", "input_tokens", "output_tokens",
             "screens", "denials", "approvals_required")
_DECLARED_FIELDS = ("version", "config_digest", "model")
_REACTIONS = ("alert", "contain")
#: Screening rules that say nothing about the agent's own behaviour: the plane
#: was off, the agent was already contained, or Second Shift could not finish
#: the check. They are not recorded, so an outage here cannot look like drift
#: and time spent contained cannot keep an agent contained after release.
_NOT_JUDGED_RULES = frozenset({"disabled", "contained", "halted", "screen_error",
                               "approval_unavailable", "approval_backlog"})
_APPROVAL_RULE = "approval_required"

#: ``[agent_drift]`` number settings: name -> (type, default, lowest, highest).
_NUMBER_SETTINGS: dict[str, tuple[type, float, float, float]] = {
    "baseline_days": (int, 14, 1, _MAX_BASELINE_DAYS),
    "window_days": (int, 3, 1, _MAX_WINDOW_DAYS),
    "min_runs": (int, 5, 1, 1000),
    "min_screens": (int, 10, 1, 1000),
    "tool_mix_min_samples": (int, 20, 5, 10000),
    "tool_mix_threshold": (float, 0.15, 0.01, 1.0),
    "volume_ratio": (float, 3.0, 1.1, 100.0),
    "cost_ratio": (float, 2.0, 1.1, 100.0),
    "denial_rate_rise": (float, 0.15, 0.01, 1.0),
    "failure_rate_rise": (float, 0.20, 0.01, 1.0),
    # how often the web app compares every agent with its baseline
    "check_minutes": (int, 15, 1, 1440),
    # how long an agent that used to report may stay quiet before it is flagged
    "silent_hours": (int, 48, 1, 720),
    # days after a baseline is approved when findings are recorded but neither
    # alerted nor allowed to contain the agent (0 turns the learning period off)
    "learning_days": (int, 14, 0, 365),
}

_NOT_RECORDED = ("This could not be written to the audit log, so nothing was changed. "
                 "Try again; if it keeps failing, check where the audit log is stored.")
_OFF_REASON = ("Drift detection is turned off, so this agent is not being "
               "compared with its baseline.")


class AgentDriftError(Exception):
    """Operator-facing failure (bad input, unknown agent, too little data)."""


class AgentDriftStoreError(AgentDriftError):
    """The saved drift record exists but cannot be read."""


def js_divergence(p: Mapping[str, Any], q: Mapping[str, Any]) -> float:
    """Jensen-Shannon divergence between two count maps, in bits: 0.0 for the
    same mix, 1.0 for mixes with nothing in common. Counts need not add up to
    one, and anything that is not a positive number is ignored. With an empty
    side there is nothing to compare and the result is 0.0."""
    left, right = _distribution(p), _distribution(q)
    if not left or not right:
        return 0.0
    total = 0.0
    for key in left.keys() | right.keys():
        a, b = left.get(key, 0.0), right.get(key, 0.0)
        middle = (a + b) / 2
        if a > 0:
            total += a * math.log2(a / middle)
        if b > 0:
            total += b * math.log2(b / middle)
    return min(1.0, max(0.0, total / 2))


def _distribution(counts: Mapping[str, Any]) -> dict[str, float]:
    kept = {key: float(value) for key, value in counts.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value > 0}
    total = sum(kept.values())
    return {key: value / total for key, value in kept.items()} if total > 0 else {}


def change_ratio(baseline: float, current: float, *, floor: float = 0.0) -> float:
    """How many times its baseline value a measure now is (3.0 tripled, 0.5
    halved). Both sides are raised to ``floor`` first. From nothing to nothing
    is 1.0; from nothing to something is infinite."""
    was, now = max(baseline, floor), max(current, floor)
    if was <= 0:
        return 1.0 if now <= 0 else math.inf
    return now / was


def share(part: float, whole: float) -> float:
    """``part`` as a fraction of ``whole``, 0.0 when there is no whole."""
    if whole <= 0:
        return 0.0
    return min(1.0, max(0.0, part / whole))


def _stepped(value: float, threshold: float, at: str, beyond: str) -> str:
    """Severity ``at`` once past the threshold, ``beyond`` at twice it."""
    return beyond if value >= 2 * threshold else at


def settings() -> dict:
    """The validated ``[agent_drift]`` section.

    ``enable`` (default on), ``baseline_days``, ``window_days``, ``min_runs``,
    ``min_screens``, ``tool_mix_min_samples``, ``check_minutes``, ``silent_hours``, one threshold per
    finding, and
    ``learning_days`` (days after a baseline is approved when findings are
    recorded but not alerted or acted on; 14, 0 turns it off) and
    ``on_drift`` ("alert", the default, or "contain"). Numbers outside their
    range are clamped; anything malformed, or a section that cannot be read,
    falls back to the default. ``MAVERICK_AGENT_DRIFT=0/1`` overrides
    ``enable``."""
    section = _section()
    flag = section.get("enable")
    out: dict[str, Any] = {"enable": flag if isinstance(flag, bool) else True}
    for name, (kind, default, low, high) in _NUMBER_SETTINGS.items():
        out[name] = _clamped(section.get(name), kind, default, low, high)
    out["window_days"] = min(out["window_days"], out["baseline_days"])
    reaction = section.get("on_drift")
    reaction = reaction.strip().lower() if isinstance(reaction, str) else ""
    out["on_drift"] = reaction if reaction in _REACTIONS else "alert"
    from .config import env_flag
    override = env_flag("MAVERICK_AGENT_DRIFT")
    if override is not None:
        out["enable"] = override
    return out


def _section() -> dict:
    try:
        from .config import load_config
        section = (load_config() or {}).get("agent_drift")
    except Exception:
        return {}
    return section if isinstance(section, dict) else {}


def _clamped(raw: Any, kind: type, default: float, low: float, high: float) -> Any:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return kind(default)
    if not math.isfinite(raw) or (kind is int and raw != int(raw)):
        return kind(default)
    return kind(max(low, min(high, raw)))


def enabled() -> bool:
    """Whether drift detection is active: on by default wherever outside-agent
    governance is on, off with ``[agent_drift] enable = false`` or
    ``MAVERICK_AGENT_DRIFT=0``."""
    return _active(settings())


def _active(cfg: dict) -> bool:
    if not cfg["enable"]:
        return False
    from . import external_agents
    return bool(external_agents.enabled())


def store_path() -> Path:
    """The drift record (``external_agents_drift.json``), in the same
    tenant-scoped directory as the enrollment sidecar."""
    from .external_agents import registry_path
    return registry_path().with_name("external_agents_drift.json")


def _load_store(path: Path | None = None) -> dict[str, dict]:
    """Every agent's drift record. A missing file is an empty store. A file
    that cannot be read or understood raises, so no caller mistakes it for
    "nothing recorded" and nothing is written over it."""
    path = path or store_path()
    from .record_documents import at
    try:
        text = at(path).read_text()
        if text is None:
            return {}
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("version") != SCHEMA_VERSION:
            raise ValueError("unknown drift store layout")
        agents = data.get("agents")
        if not isinstance(agents, dict) or not all(
                _well_formed(record) for record in agents.values()):
            raise ValueError("drift store holds a malformed agent record")
        return agents
    except (OSError, UnicodeError, ValueError, RecursionError) as e:
        raise AgentDriftStoreError(
            "The saved drift record cannot be read, so nothing was changed. "
            "Restore it from a backup, or move the file aside to start a new "
            "record.") from e


def _well_formed(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    days = record.get("days")
    return (isinstance(days, dict)
            and all(isinstance(day, dict) for day in days.values())
            and isinstance(record.get("baseline") or {}, dict)
            and all(isinstance(record.get(name) or {}, dict)
                    for name in ("config", "reported", "acknowledged")))


def _dump(agents: dict[str, dict]) -> str:
    return json.dumps({"version": SCHEMA_VERSION, "agents": agents},
                      sort_keys=True, separators=(",", ":"))


@contextmanager
def _editing() -> Iterator[dict[str, dict]]:
    """The store, held under its cross-process lock for one read-modify-write.

    Whatever the block leaves in the mapping is written back, atomically, when
    it differs from what was read. An unreadable file raises before the block
    runs and a block that raises writes nothing, so a file this module could
    not read is never replaced. The block must not take the enrollment sidecar
    lock (``external_agents.contain`` and friends): the gateway may come to
    call a hook while holding that lock, and the two orders would deadlock."""
    from .record_documents import at
    path = store_path()
    record = at(path)
    with record.locked():
        agents = _load_store(path)
        before = _dump(agents)
        yield agents
        after = _dump(agents)
        if after != before:
            record.write_text(after)


def _enrolled_ids() -> dict[str, float]:
    """The agents enrolled right now, each with the time it was enrolled. A
    strict read: an unreadable enrollment sidecar raises instead of looking
    like an empty roster."""
    from . import external_agents
    return {agent_id: _amount(_dict(entry).get("enrolled_at"))
            for agent_id, entry in external_agents._load_sidecar(strict=True).items()}


def _same_enrollment(record: dict, enrolled_at: float) -> bool:
    """Whether the record was started under the enrollment that exists now. An
    id that was removed and enrolled again is a different agent: it must not
    inherit the old one's baseline, findings or acknowledgements."""
    stamp = record.get("enrolled_at")
    return stamp is None or abs(_amount(stamp) - enrolled_at) < 1.0


def _fresh_record(enrolled_at: float) -> dict:
    return {"days": {}, "config": {}, "baseline": None, "reported": {},
            "acknowledged": {}, "enrolled_at": enrolled_at}


def _current_record(agents: dict[str, dict], agent_id: str, enrolled: dict[str, float]) -> dict | None:
    """The stored record, read-only, or ``None`` when there is none for the
    enrollment that exists now."""
    record = agents.get(agent_id)
    if record is None or agent_id not in enrolled:
        return None
    return record if _same_enrollment(record, enrolled[agent_id]) else None


def forget(agent_id: str) -> bool:
    """Drop everything recorded about an agent. Called when it is removed, so
    a later agent enrolled under the same id starts clean. Never raises."""
    try:
        with _editing() as agents:
            return agents.pop(agent_id, None) is not None
    except Exception:
        _hook_failed()
        return False


def _record_for(agents: dict[str, dict], agent_id: str, enrolled: dict[str, float]) -> dict | None:
    """The agent's record, created on first sight. ``None`` when the agent is
    not enrolled or the store is full. Making room for a new agent drops the
    records of agents that are no longer enrolled."""
    if agent_id not in enrolled:
        return None
    if agent_id in agents and not _same_enrollment(agents[agent_id], enrolled[agent_id]):
        del agents[agent_id]
    if agent_id not in agents:
        for gone in [known for known in agents if known not in enrolled]:
            del agents[gone]
        if len(agents) >= _MAX_AGENTS:
            return None
        agents[agent_id] = _fresh_record(enrolled[agent_id])
    agents[agent_id].setdefault("enrolled_at", enrolled[agent_id])
    return agents[agent_id]


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _amount(value: Any) -> float:
    """A non-negative finite number from untrusted input; junk reads as 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 0.0
    try:
        number = float(value)
    except ValueError:
        return 0.0
    except OverflowError:  # a whole number too large for a float
        return float(_MAX_COUNT) if value > 0 else 0.0
    if not math.isfinite(number) or number <= 0:
        return 0.0
    return min(number, float(_MAX_COUNT))


def _count(value: Any) -> int:
    return int(_amount(value))


def _rank(severity: Any) -> int:
    return _RANK.get(severity, 0) if isinstance(severity, str) else 0


def _label(value: Any, *, limit: int = 80) -> str:
    """A short display-safe name, or "" when the value is not one. Names come
    from the agent's platform, so anything long, oddly spelled or shaped like
    a secret is refused instead of being stored and shown."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > limit or not _LABEL.fullmatch(text):
        return ""
    return "" if _looks_secret(text) else text


def _looks_secret(text: str) -> bool:
    try:
        from .safety.secret_detector import redact
        return redact(text)[0] != text
    except Exception:
        return True  # cannot check it, so do not keep it


def _fingerprint(value: Any) -> str:
    """A configuration value as stored: the value itself when it is a short
    plain label, otherwise a digest of it. Either way a change shows, and
    arbitrary text from the agent's platform is never kept. "" for nothing."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    text = (repr(value) if isinstance(value, float) else str(value)).strip()
    if not text:
        return ""
    return _label(text, limit=128) or "sha256:" + hashlib.sha256(
        text.encode("utf-8", "replace")).hexdigest()[:32]


def _now(now: float | None) -> float:
    if now is None:
        return time.time()
    moment = float(now)
    return moment if math.isfinite(moment) else time.time()


def _epoch_day(moment: float) -> int:
    return int(moment // _DAY_SECONDS)


def _day_key(epoch_day: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(epoch_day * _DAY_SECONDS))


def _elapsed_days(first_day: int, moment: float) -> float:
    """Days from the start of ``first_day`` (UTC) to ``moment``, never less
    than one: a few hours of activity are not stretched into a daily rate."""
    return max(moment / _DAY_SECONDS - first_day, 1.0)


def _empty_totals() -> dict[str, Any]:
    return {**dict.fromkeys(_COUNTERS, 0), "cost_dollars": 0.0, "tools": {}}


def _add(total: dict, day: dict) -> None:
    """Add one stored day (read defensively) into ``total``."""
    for name in _COUNTERS:
        total[name] = min(_MAX_COUNT, total[name] + _count(day.get(name)))
    total["cost_dollars"] = round(total["cost_dollars"] + _amount(day.get("cost_dollars")), 6)
    for tool, times in _dict(day.get("tools")).items():
        if _count(times):
            total["tools"][tool] = min(_MAX_COUNT, total["tools"].get(tool, 0) + _count(times))


def _window(days: dict, first: int, last: int) -> dict:
    """Totals over the UTC days ``first`` to ``last`` inclusive."""
    total = _empty_totals()
    for epoch_day in range(first, last + 1):
        _add(total, _dict(days.get(_day_key(epoch_day))))
    return total


def _stored_totals(baseline: dict) -> dict:
    total = _empty_totals()
    _add(total, _dict(baseline.get("totals")))
    return total


def _measures(totals: dict, days: float) -> dict:
    """One window's totals plus the rates drift is judged on."""
    runs = totals["runs"]
    return {**totals, "tools": dict(totals["tools"]), "days": days,
            "runs_per_day": runs / days if days > 0 else 0.0,
            "cost_per_run": totals["cost_dollars"] / runs if runs else 0.0,
            "denial_rate": share(totals["denials"], totals["screens"]),
            "failure_rate": share(totals["failures"], runs)}


def _rounded(measures: dict) -> dict:
    return {name: round(value, 4) if isinstance(value, float) else value
            for name, value in measures.items()}


def observe_screen(agent_id: str, tool: str, *, allowed: bool, rule: str = "",
                   now: float | None = None) -> None:
    """Count one screening decision for an enrolled agent: the tool asked for,
    and whether it was allowed, refused or sent to a person for approval.
    Never raises; a no-op when drift detection is off."""
    def note(record: dict, moment: float) -> bool:
        if rule in _NOT_JUDGED_RULES:
            return False
        day = _day_bucket(record, moment)
        _bump(day, "screens")
        if rule == _APPROVAL_RULE:
            _bump(day, "approvals_required")
        elif not allowed:
            _bump(day, "denials")
        _count_tool(_known_tools(record), day, tool)
        return True

    _observe(agent_id, now, note)


def observe_run(agent_id: str, *, cost_dollars: float = 0.0, input_tokens: int = 0,
                output_tokens: int = 0, tool_calls: int = 0, outcome: str = "",
                tools: Any = (), declared: dict | None = None,
                now: float | None = None) -> None:
    """Count one finished run for an enrolled agent. ``tools`` is a list of
    the tool names the run used (names only); ``declared`` may carry the
    agent's own ``version``, ``config_digest`` and ``model``. Never raises; a
    no-op when drift detection is off."""
    def note(record: dict, moment: float) -> bool:
        day = _day_bucket(record, moment)
        _bump(day, "runs")
        if str(outcome or "").strip().lower() not in ("", "success", "done", "ok"):
            _bump(day, "failures")
        _bump(day, "tool_calls", _count(tool_calls))
        _bump(day, "input_tokens", _count(input_tokens))
        _bump(day, "output_tokens", _count(output_tokens))
        day["cost_dollars"] = round(day["cost_dollars"] + _amount(cost_dollars), 6)
        known = _known_tools(record)
        names = list(tools) if isinstance(tools, (list, tuple, set, frozenset)) else []
        for name in names[:_MAX_TOOLS_PER_RUN]:
            _count_tool(known, day, name)
        _note_declared(record, declared, moment)
        return True

    _observe(agent_id, now, note)


def observe_declared(agent_id: str, declared: dict | None, *, now: float | None = None) -> None:
    """Note the build an agent says it is (``version``, ``config_digest``, ``model``) when it opens a run,
    before it has done anything. Counts nothing else. Never raises; a no-op when drift detection is off."""
    def note(record: dict, moment: float) -> bool:
        _note_declared(record, declared, moment)
        return isinstance(declared, Mapping)

    _observe(agent_id, now, note)


def observe_discovered(agent_id: str, *, version_digest: str, binding_strength: str = "",
                       source: str = "", now: float | None = None,
                       description: Mapping[str, Any] | None = None) -> None:
    """Remember the configuration fingerprint a discovery connector read from
    the agent's home platform. This is the authoritative fingerprint: it does
    not depend on what the agent says about itself. ``description`` is the
    small description of the set-up that went with it (``agent_watch_changes``);
    it is validated again here and kept beside the fingerprint, so a baseline
    approved later keeps the description that was current with it. Never
    raises; a no-op when drift detection is off."""
    def note(record: dict, moment: float) -> bool:
        digest = _fingerprint(version_digest)
        if not digest:
            return False
        kept = {
            "version_digest": digest,
            "binding_strength": _label(binding_strength, limit=40),
            "source": _label(source),
            "seen_at": moment,
        }
        described = agent_watch_changes.clean(kept["source"], description)
        if described:
            kept["description"] = described
        _config_of(record)["discovered"] = kept
        return True

    _observe(agent_id, now, note)


def _observe(agent_id: str, now: float | None, note: Callable[[dict, float], bool]) -> None:
    """Apply one hook's update to the agent's record. Failures stop here: the
    caller is a governance path that must not be disturbed."""
    try:
        if not enabled():
            return
        moment = _now(now)
        with _editing() as agents:
            record = _record_for(agents, agent_id, _enrolled_ids())
            if record is not None and note(record, moment):
                _trim_days(record)
                record["last_observed_at"] = max(
                    moment, _amount(record.get("last_observed_at")))
    except Exception:
        _hook_failed()


_hook_failure_logged = False


def _hook_failed() -> None:
    """Log a failed observation: loudly once, quietly after that."""
    global _hook_failure_logged
    level = logging.DEBUG if _hook_failure_logged else logging.WARNING
    _hook_failure_logged = True
    log.log(level, "agent_drift: an observation could not be recorded", exc_info=True)


def _day_bucket(record: dict, moment: float) -> dict:
    """The record's totals for the UTC day of ``moment``, created if absent."""
    days = record["days"]
    key = _day_key(_epoch_day(moment))
    bucket = _empty_totals()
    _add(bucket, _dict(days.get(key)))
    days[key] = bucket
    return bucket


def _trim_days(record: dict) -> None:
    days = record["days"]
    for stale in sorted(days)[:-_MAX_DAYS]:
        del days[stale]


def _bump(day: dict, name: str, by: int = 1) -> None:
    day[name] = min(_MAX_COUNT, day[name] + by)


def _known_tools(record: dict) -> set[str]:
    """Every tool name the record already holds, the baseline included."""
    known = set(_dict(_dict(record.get("baseline")).get("totals")).get("tools") or ())
    for day in record["days"].values():
        known.update(_dict(day.get("tools")))
    known.discard(_OTHER_TOOL)
    return known


def _tool_name(tool: Any) -> str:
    """The name a tool is counted under: its own when it is short and plain,
    otherwise a digest, so two unshowable names stay two tools and a new one
    still reads as new. Only a missing name falls back to "(other)"."""
    name = _label(tool)
    if name:
        return name
    if not isinstance(tool, str) or not tool.strip():
        return _OTHER_TOOL
    return _UNNAMED + hashlib.sha256(tool.strip().encode("utf-8", "replace")).hexdigest()[:12]


def _count_tool(known: set[str], day: dict, tool: Any) -> None:
    name = _tool_name(tool)
    if name != _OTHER_TOOL and name not in known:
        if len(known) >= _MAX_TOOLS:
            name = _OTHER_TOOL
        else:
            known.add(name)
    day["tools"][name] = min(_MAX_COUNT, day["tools"].get(name, 0) + 1)


def _config_of(record: dict) -> dict:
    if not isinstance(record.get("config"), dict):
        record["config"] = {}
    return record["config"]


def _note_declared(record: dict, declared: Any, moment: float) -> None:
    if not isinstance(declared, Mapping):
        return
    seen = {name: _fingerprint(declared.get(name)) for name in _DECLARED_FIELDS}
    seen = {name: value for name, value in seen.items() if value}
    if seen:
        config = _config_of(record)
        config["declared"] = {**_dict(config.get("declared")), **seen, "seen_at": moment}


def approve_baseline(agent_id: str, *, actor: str, window_days: int | None = None,
                     force: bool = False, now: float | None = None) -> dict:
    """Approve the agent's last ``window_days`` (default ``[agent_drift]
    baseline_days``) of recorded activity, with the configuration fingerprints
    seen so far, as its baseline. Records who approved it and when, clears
    earlier findings and acknowledgements, and is audited.

    Raises :class:`AgentDriftError`, saying why, when the agent is not
    enrolled, no approver is named, or too little activity has been recorded
    to make a useful baseline. ``force=True`` approves a thin baseline anyway."""
    who = _actor(actor)
    cfg = settings()
    span = _baseline_span(window_days, cfg)
    moment = _now(now)
    if not _active(cfg):
        raise AgentDriftError(
            "Drift detection is turned off. Turn it on before approving a baseline.")
    with _editing() as agents:
        enrolled = _enrolled_ids()
        if agent_id not in enrolled:
            raise AgentDriftError(
                f"{agent_id!r} is not an enrolled agent, so it has no baseline to approve.")
        record = _record_for(agents, agent_id, enrolled)
        if record is None:
            raise AgentDriftError(
                "The drift record is full; no baseline can be kept for another agent.")
        snapshot = _snapshot(record, span, moment)
        enough = _enough(snapshot["totals"], cfg)
        if not enough and not force:
            raise AgentDriftError(_too_little(agent_id, snapshot["totals"], span, cfg))
        snapshot.update(approved_by=who, approved_at=moment, forced=not enough)
        if not _audit("agent_baseline_approved", agent_id, approved_by=who, window_days=span,
                      runs=snapshot["totals"]["runs"], screens=snapshot["totals"]["screens"],
                      tools=len(snapshot["totals"]["tools"]), forced=not enough,
                      replaced=isinstance(record.get("baseline"), dict)):
            raise AgentDriftError(_NOT_RECORDED)
        record.update(baseline=snapshot, reported={}, acknowledged={})
    return _baseline_view(snapshot)


def baseline(agent_id: str) -> dict | None:
    """The agent's approved baseline, or ``None`` when it has none."""
    record = _current_record(_load_store(), agent_id, _enrolled_ids())
    approved = _dict(record).get("baseline")
    return _baseline_view(approved) if isinstance(approved, dict) else None


def approve_declared_configuration(agent_id: str, *, version: str, config_digest: str, model: str, actor: str) -> bool:
    """Make the configuration a released agent declares the approved one.

    The agent factory calls this when it releases a version: that version's fingerprints (``version``,
    ``config_digest``, ``model``) become what the baseline expects to see, so a run that reports them raises no
    ``config_changed`` finding and one that reports anything else does. Only the declared fingerprints change; the
    baseline's activity figures are left alone. Does nothing, and says so (``False``), when drift detection is off.
    Raises :class:`AgentDriftError` when the agent is not enrolled or no one is named."""
    who = _actor(actor)
    if not _active(settings()):
        return False
    seen = {name: _fingerprint(value) for name, value in
            (("version", version), ("config_digest", config_digest), ("model", model))}
    seen = {name: value for name, value in seen.items() if value}
    with _editing() as agents:
        enrolled = _enrolled_ids()
        if agent_id not in enrolled:
            raise AgentDriftError(f"{agent_id!r} is not an enrolled agent.")
        record = _record_for(agents, agent_id, enrolled)
        if record is None:
            raise AgentDriftError("The drift record is full; no configuration can be kept for another agent.")
        config = _config_of(record)
        config["declared"] = {**_dict(config.get("declared")), **seen}
        approved = record.get("baseline")
        if isinstance(approved, dict):
            base = approved.get("config")
            if not isinstance(base, dict):
                base = approved["config"] = {}
            base["declared"] = {**_dict(base.get("declared")), **seen}
        if not _audit("agent_declared_configuration_approved", agent_id, approved_by=who, **seen):
            raise AgentDriftError(_NOT_RECORDED)
    return True


def _actor(actor: Any) -> str:
    who = actor.strip()[:200] if isinstance(actor, str) else ""
    if not who:
        raise AgentDriftError("Say who is making this decision; it is recorded with it.")
    return who


def _baseline_span(window_days: Any, cfg: dict) -> int:
    if window_days is None:
        return cfg["baseline_days"]
    if (isinstance(window_days, bool) or not isinstance(window_days, int)
            or not 1 <= window_days <= _MAX_BASELINE_DAYS):
        raise AgentDriftError(
            f"window_days must be a whole number from 1 to {_MAX_BASELINE_DAYS}.")
    return window_days


def _snapshot(record: dict, span: int, moment: float) -> dict:
    last = _epoch_day(moment)
    first = last - span + 1
    days = record["days"]
    started = next((day for day in range(first, last + 1) if _day_key(day) in days), first)
    return {"window_days": span, "from_day": _day_key(first), "to_day": _day_key(last),
            "days": round(_elapsed_days(started, moment), 4),
            # whole days of activity behind the rate; none means the rate is a guess
            "whole_days": last - started,
            "totals": _window(days, first, last),
            "config": copy.deepcopy(_dict(record.get("config")))}


def _enough(totals: dict, cfg: dict) -> bool:
    return totals["runs"] >= cfg["min_runs"] or totals["screens"] >= cfg["min_screens"]


def _too_little(agent_id: str, totals: dict, span: int, cfg: dict) -> str:
    return (f"There is not enough activity to approve a baseline for {agent_id}: "
            f"{_activity(totals)} in the last {_plural(span, 'day')}, where at least "
            f"{_needed(cfg)} are needed. Wait for more activity, or approve anyway "
            "with force.")


def _activity(totals: dict) -> str:
    return (f"{_plural(totals['runs'], 'run')} and "
            f"{_plural(totals['screens'], 'screened action')}")


def _needed(cfg: dict) -> str:
    return (f"{_plural(cfg['min_runs'], 'run')} or "
            f"{_plural(cfg['min_screens'], 'screened action')}")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _baseline_view(approved: dict) -> dict:
    measures = _measures(_stored_totals(approved), _amount(approved.get("days")) or 1.0)
    return {"approved_at": approved.get("approved_at"),
            "approved_by": approved.get("approved_by", ""),
            "window_days": approved.get("window_days"),
            "from_day": approved.get("from_day"), "to_day": approved.get("to_day"),
            "forced": bool(approved.get("forced")),
            **_rounded(measures),
            "config": _config_view(_dict(approved.get("config")))}


def _config_view(config: dict) -> dict:
    return {group: dict(_dict(config.get(group))) for group in ("declared", "discovered")}


def evaluate(agent_id: str, *, now: float | None = None) -> dict:
    """Compare the agent's recent activity with its approved baseline.

    Returns ``{"state", "reason", "findings", "findings_count",
    "highest_severity", "baseline", "current", "compared", "skipped", ...}``.
    ``state`` is ``"no_baseline"`` (nothing approved yet), ``"learning"`` (a
    baseline exists but there is too little activity to compare, or detection
    is off), ``"within_baseline"`` or ``"drifted"``. Each finding carries a
    ``key``, ``kind``, ``severity``, plain-language ``summary`` and the
    ``baseline`` and ``current`` values; acknowledged findings stay listed but
    do not count. Reads only; raises :class:`AgentDriftStoreError` when the
    record cannot be read."""
    cfg = settings()
    record = _current_record(_load_store(), agent_id, _enrolled_ids())
    return _evaluate_record(agent_id, record, cfg, _now(now), active=_active(cfg))


def _evaluate_record(agent_id: str, record: dict | None, cfg: dict, moment: float,
                     *, active: bool) -> dict:
    record = record or {}
    approved = record.get("baseline")
    days = _dict(record.get("days"))
    today = _epoch_day(moment)
    out: dict[str, Any] = {
        "agent_id": agent_id, "enabled": active, "evaluated_at": moment,
        "state": "no_baseline", "reason": "", "findings": [], "findings_count": 0,
        "highest_severity": "", "baseline": None, "current": None,
        "compared": [], "skipped": []}
    if not isinstance(approved, dict):
        return _without_baseline(out, days, cfg, moment, active=active)
    out["baseline"] = _baseline_view(approved)
    ends = _learning_ends_at(approved, cfg)
    out["learning_period"] = {"active": moment < ends, "ends_at": ends if ends > 0 else None,
                              "days": cfg["learning_days"]}
    # Drift is movement after approval, so the window never reaches back
    # before the day the baseline was approved.
    first = max(today - cfg["window_days"] + 1,
                min(today, _epoch_day(_amount(approved.get("approved_at")))))
    current = _measures(_window(days, first, today), float(today - first + 1))
    out["current"] = _rounded(current)
    # Today is still filling up; ``_volume`` needs the whole days on their own.
    current["whole_days"] = today - first
    current["whole_day_runs"] = _window(days, first, today - 1)["runs"]
    if not active:
        out.update(state="learning", reason=_OFF_REASON)
        return out
    base = _measures(_stored_totals(approved), _amount(approved.get("days")) or 1.0)
    base["whole_days"] = _count(approved.get("whole_days", 1))
    findings = _new_tool_findings(base, current)
    findings.extend(_silence(base, record, cfg, moment))
    for name, compare in _RATE_CHECKS:
        found = compare(base, current, cfg)
        (out["skipped"] if found is None else out["compared"]).append(name)
        findings.extend(found or [])
    findings.extend(_config_findings(_dict(approved.get("config")),
                                     _dict(record.get("config"))))
    _apply_acknowledgements(findings, _dict(record.get("acknowledged")),
                            _dict(record.get("reported")))
    for finding in findings:
        finding["learning"] = out["learning_period"]["active"] and not _always_alerts(finding)
    _settle_state(out, findings, base, current)
    return out


def _learning_ends_at(approved: dict, cfg: dict) -> float:
    """When the learning period after the baseline's approval ends (0.0 with
    none)."""
    if not cfg["learning_days"]:
        return 0.0
    return _amount(approved.get("approved_at")) + cfg["learning_days"] * _DAY_SECONDS


def _always_alerts(finding: dict) -> bool:
    """A high-severity change to the agent's set-up on its home platform is
    alerted (and may contain the agent) even in the learning period."""
    return (finding["kind"] == "config_changed" and finding.get("source") == "discovery"
            and finding["severity"] == HIGH)


def _without_baseline(out: dict, days: dict, cfg: dict, moment: float, *, active: bool) -> dict:
    """With nothing approved, ``current`` covers the days an approval would
    capture and ``ready_to_approve`` says whether one would be accepted."""
    today = _epoch_day(moment)
    span = cfg["baseline_days"]
    totals = _window(days, today - span + 1, today)
    out["current"] = _rounded(_measures(totals, float(span)))
    out["ready_to_approve"] = active and _enough(totals, cfg)
    reason = "No baseline has been approved for this agent yet. "
    if not active:
        reason += "Drift detection is turned off."
    elif out["ready_to_approve"]:
        reason += "Enough activity has been recorded to approve one."
    else:
        reason += (f"So far there have been {_activity(totals)} in the last "
                   f"{_plural(span, 'day')}; {_needed(cfg)} are needed.")
    out["reason"] = reason
    return out


def _settle_state(out: dict, findings: list[dict], base: dict, current: dict) -> None:
    still_open = [f for f in findings if not f["acknowledged"]]
    out["findings"] = sorted(findings, key=lambda f: (-_RANK[f["severity"]], f["key"]))
    out["findings_count"] = len(still_open)
    out["highest_severity"] = max((f["severity"] for f in still_open),
                                  key=_RANK.__getitem__, default="")
    if still_open:
        out["state"] = "drifted"
        out["reason"] = (f"{_plural(len(still_open), 'finding')} "
                         f"{'needs' if len(still_open) == 1 else 'need'} review.")
    elif not out["compared"]:
        out["state"] = "learning"
        out["reason"] = (
            "There is not enough activity to compare with the approved baseline yet: "
            f"{_activity(current)} recently, against {_activity(base)} in the baseline.")
    else:
        out["state"] = "within_baseline"
        out["reason"] = "Recent activity matches the approved baseline."


def _finding(kind: str, severity: str, summary: str, baseline_value: Any,
             current_value: Any, *, key: str = "", **extra: Any) -> dict:
    return {"key": key or kind, "kind": kind, "severity": severity, "summary": summary,
            "baseline": baseline_value, "current": current_value, **extra}


def _new_tool_findings(base: dict, current: dict) -> list[dict]:
    """A tool in the recent window that the baseline never saw. Refused
    attempts count too: asking for an unknown tool is the signal."""
    found = []
    for tool, times in sorted(current["tools"].items()):
        was = base["tools"].get(tool, 0)
        if tool == _OTHER_TOOL:
            # "(other)" is tools that are not tracked by name, so having some
            # in the baseline says nothing about which ones: a rise in their
            # share is the only sign that a new one arrived.
            before = share(was, sum(base["tools"].values()))
            if was and share(times, sum(current["tools"].values())) <= before + _OTHER_RISE:
                continue
            what = "tools that are not tracked by name, more than in its approved baseline"
        elif was > 0:
            continue
        elif tool.startswith(_UNNAMED):
            what = ("a tool that was not in its approved baseline and whose name cannot "
                    f"be shown (reference {tool})")
        else:
            what = f"a tool that was not in its approved baseline: {tool}"
        found.append(_finding(
            "new_tool", HIGH,
            f"This agent used or asked to use {what} ({_plural(times, 'time')} recently).",
            was, times, key=f"new_tool:{tool}", tool=tool))
    return found


def _silence(base: dict, record: dict, cfg: dict, moment: float) -> list[dict]:
    """An agent whose baseline shows steady activity and that has reported
    nothing for a long time. Quiet is not the same as safe: it may have
    stopped, or it may be working without reporting. The wait is at least
    ``silent_hours`` and at least three of its usual gaps, so an agent that
    only works weekly is not flagged after two days."""
    last = _amount(record.get("last_observed_at"))
    per_day = (base["runs"] + base["screens"]) / (base["days"] or 1.0)
    enough = base["runs"] >= cfg["min_runs"] or base["screens"] >= cfg["min_screens"]
    if not last or not enough or per_day <= 0:
        return []
    quiet = moment - last
    wait = max(cfg["silent_hours"] * 3600.0, 3 * _DAY_SECONDS / per_day)
    if quiet < wait:
        return []
    days = quiet / _DAY_SECONDS
    return [_finding(
        "silent", MEDIUM,
        f"This agent has reported nothing for {days:.1f} days, though its approved baseline "
        f"shows about {per_day:.1f} runs and checks a day. It may have stopped, or it may be "
        "working without reporting.",
        round(per_day, 2), 0, quiet_days=round(days, 2))]


def _tool_mix(base: dict, current: dict, cfg: dict) -> list[dict] | None:
    need = cfg["tool_mix_min_samples"]
    if sum(base["tools"].values()) < need or sum(current["tools"].values()) < need:
        return None
    distance, limit = js_divergence(base["tools"], current["tools"]), cfg["tool_mix_threshold"]
    if distance < limit:
        return []
    return [_finding(
        "tool_mix", _stepped(distance, limit, LOW, MEDIUM),
        "The mix of tools this agent uses has shifted away from its approved baseline "
        f"(difference score {distance:.2f}; 0 is the same mix, 1 is nothing in common).",
        _top_shares(base["tools"]), _top_shares(current["tools"]),
        score=round(distance, 4), threshold=limit)]


def _top_shares(tools: dict, top: int = 5) -> dict[str, float]:
    total = sum(tools.values())
    largest = sorted(tools.items(), key=lambda item: (-item[1], item[0]))[:top]
    return {tool: round(share(times, total), 4) for tool, times in largest}


def _volume(base: dict, current: dict, cfg: dict) -> list[dict] | None:
    """Runs per day against the baseline. The day in progress is still filling
    up, so it is never stretched into a daily rate: a rise is judged on the
    whole days in the window, or on the window with today counted as a whole
    day if that is higher (a morning batch is not a spike); a fall is judged
    on whole days only (a quiet morning is not a drop)."""
    if base.get("whole_days", 1) < 1:
        return None  # the baseline has no completed day to take a daily rate from
    need, limit, was = cfg["min_runs"], cfg["volume_ratio"], base["runs_per_day"]
    whole = current["whole_days"]
    can_rise = current["runs"] >= need
    can_fall = whole >= 1 and was * whole >= need
    if base["runs"] < need or not (can_rise or can_fall):
        return None
    settled = current["whole_day_runs"] / whole if whole else 0.0
    now = max(current["runs_per_day"], settled)
    ratio = change_ratio(was, now)
    if can_rise and ratio >= limit:
        return [_finding(
            "volume", _stepped(ratio, limit, MEDIUM, HIGH),
            f"This agent is running about {ratio:.1f} times as often as in its approved "
            f"baseline: {now:.1f} runs a day, up from {was:.1f}.",
            round(was, 2), round(now, 2), key="volume:up",
            ratio=round(ratio, 2), threshold=limit)]
    ratio = change_ratio(was, settled)
    if can_fall and ratio <= 1 / limit:
        return [_finding(
            "volume", LOW,
            "This agent is running far less often than in its approved baseline: "
            f"{settled:.1f} runs a day, down from {was:.1f}.",
            round(was, 2), round(settled, 2), key="volume:down",
            ratio=round(ratio, 2), threshold=limit)]
    return []


def _cost(base: dict, current: dict, cfg: dict) -> list[dict] | None:
    need = cfg["min_runs"]
    if base["runs"] < need or current["runs"] < need:
        return None
    was, now = base["cost_per_run"], current["cost_per_run"]
    ratio, limit = change_ratio(was, now, floor=_COST_FLOOR), cfg["cost_ratio"]
    numbers = {"ratio": round(ratio, 2), "threshold": limit}
    if ratio >= limit:
        return [_finding(
            "cost", _stepped(ratio, limit, MEDIUM, HIGH),
            f"Each run now costs about {ratio:.1f} times what it did in the approved "
            f"baseline: ${now:,.2f} a run, up from ${was:,.2f}.",
            round(was, 4), round(now, 4), key="cost:up", **numbers)]
    if ratio <= 1 / limit:
        return [_finding(
            "cost", LOW,
            "Each run now costs far less than in the approved baseline: "
            f"${now:,.2f} a run, down from ${was:,.2f}.",
            round(was, 4), round(now, 4), key="cost:down", **numbers)]
    return []


def _denial_rate(base: dict, current: dict, cfg: dict) -> list[dict] | None:
    need = cfg["min_screens"]
    if base["screens"] < need or current["screens"] < need:
        return None
    was, now, limit = base["denial_rate"], current["denial_rate"], cfg["denial_rate_rise"]
    if now - was < limit:
        return []
    return [_finding(
        "denial_rate", _stepped(now - was, limit, MEDIUM, HIGH),
        "More of the actions this agent asks for are being refused: "
        f"{now:.0%} now, {was:.0%} in its approved baseline.",
        round(was, 4), round(now, 4), threshold=limit)]


def _failure_rate(base: dict, current: dict, cfg: dict) -> list[dict] | None:
    need = cfg["min_runs"]
    if base["runs"] < need or current["runs"] < need:
        return None
    was, now, limit = base["failure_rate"], current["failure_rate"], cfg["failure_rate_rise"]
    if now - was < limit:
        return []
    return [_finding(
        "failure_rate", _stepped(now - was, limit, LOW, MEDIUM),
        f"More of this agent's runs are failing: {now:.0%} now, {was:.0%} in its "
        "approved baseline.",
        round(was, 4), round(now, 4), threshold=limit)]


#: Comparisons that need a minimum sample on both sides. Each returns ``None``
#: when it had too little to go on, otherwise its findings (possibly none).
_RATE_CHECKS: tuple[tuple[str, Callable[[dict, dict, dict], list[dict] | None]], ...] = (
    ("tool_mix", _tool_mix),
    ("volume", _volume),
    ("cost", _cost),
    ("denial_rate", _denial_rate),
    ("failure_rate", _failure_rate),
)

#: Configuration comparisons: (kind, source, severity, group, field, summary).
#: A fingerprint read from the home platform is authoritative, so a change
#: there is high; what the agent says about itself is medium.
_CONFIG_CHECKS = (
    ("config_changed", "discovery", HIGH, "discovered", "version_digest",
     "The agent's configuration on its home platform no longer matches the approved one."),
    ("config_changed", "self_reported", MEDIUM, "declared", "config_digest",
     "The agent reports a configuration that no longer matches the approved one."),
    ("model_changed", "self_reported", MEDIUM, "declared", "model",
     "The agent reports a different model from the approved one."),
    ("version_changed", "self_reported", MEDIUM, "declared", "version",
     "The agent reports a different version from the approved one."),
)


def _config_findings(approved: dict, observed: dict) -> list[dict]:
    """Fingerprints that were approved and have since been seen to differ. A
    fingerprint the baseline never had cannot be compared and raises nothing."""
    found = []
    for kind, source, severity, group, field, summary in _CONFIG_CHECKS:
        was = _dict(approved.get(group)).get(field)
        now = _dict(observed.get(group)).get(field)
        if not (isinstance(was, str) and isinstance(now, str) and was and now) or was == now:
            continue
        mark = hashlib.sha256(now.encode("utf-8", "replace")).hexdigest()[:12]
        extra = _what_changed(approved, observed) if source == "discovery" else {}
        found.append(_finding(kind, severity, extra.pop("summary", summary), was, now,
                              key=f"{kind}:{source}:{mark}", source=source, **extra))
    return found


def _what_changed(approved: dict, observed: dict) -> dict:
    """For a changed platform fingerprint: the field-level difference between
    the approved description and the current one, in plain words. A baseline
    approved before descriptions were kept has none, and says so."""
    was, now = _dict(approved.get("discovered")), _dict(observed.get("discovered"))
    platform = now.get("source") if isinstance(now.get("source"), str) else ""
    found = agent_watch_changes.compare(platform, was.get("description"), now.get("description"))
    out: dict[str, Any] = {"details_recorded": found["recorded"], "changes": found["changes"],
                           "not_known": found["not_known"], "details_note": found["details"]}
    if found["recorded"]:
        out["summary"] = found["summary"]
    return out


def _apply_acknowledgements(findings: list[dict], acknowledged: dict, reported: dict) -> None:
    """Mark each finding acknowledged or open. An acknowledgement covers the
    finding at the severity it had; one that has got worse is open again."""
    for finding in findings:
        ack = _dict(acknowledged.get(finding["key"]))
        covered = bool(ack) and _RANK[finding["severity"]] <= _rank(ack.get("severity"))
        finding["acknowledged"] = covered
        if covered:
            finding["acknowledged_by"] = ack.get("by", "")
            finding["acknowledged_at"] = ack.get("at")
        first = _dict(reported.get(finding["key"])).get("at")
        if first is not None:
            finding["reported_at"] = first


def check(agent_id: str, *, now: float | None = None) -> dict:
    """Evaluate the agent and react to findings not reported before.

    Each new finding is written to the audit log (``agent_drift_detected``)
    and one alert goes out for the batch. With ``[agent_drift] on_drift =
    "contain"`` a new high-severity finding also contains the agent at the
    gateway; the default is to alert only. A finding already reported is not
    reported again while it lasts, unless it gets more severe. A finding whose
    audit row could not be written is not counted as reported, so the next
    check reports it. Returns the evaluation plus ``new_findings`` (keys),
    ``reaction`` and ``contained``. Raises :class:`AgentDriftError` for an
    agent that is not enrolled."""
    cfg = settings()
    moment = _now(now)
    enrolled = _enrolled_ids()
    if agent_id not in enrolled:
        raise AgentDriftError(f"{agent_id!r} is not an enrolled agent.")
    record = _current_record(_load_store(), agent_id, enrolled)
    result = _evaluate_record(agent_id, record, cfg, moment, active=_active(cfg))
    result.update(new_findings=[], reaction=cfg["on_drift"], contained=False)
    if not result["enabled"] or record is None:
        return result
    if not (result["findings"] or record.get("reported") or record.get("acknowledged")):
        return result  # nothing to report and nothing to forget
    reported = _dict(record.get("reported"))
    fresh = _new_findings(result["findings"], reported)
    # A high finding that could not be contained last time is tried again,
    # without being reported a second time.
    waiting = [f for f in result["findings"] if not f["acknowledged"]
               and _dict(reported.get(f["key"])).get("containment_pending")]
    contained = failed = False
    # Containment comes first and outside the store lock: if this process
    # stops before the finding is remembered, the next check contains again
    # instead of believing it was already handled.
    if cfg["on_drift"] == "contain" and (
            waiting or any(f["severity"] == HIGH and not f.get("learning") for f in fresh)):
        contained, failed = _contain(agent_id)
    new = _report_new(agent_id, cfg, moment, contained=contained, failed=failed,
                      seen={f["key"] for f in fresh})
    # Findings from the learning period are recorded above but not alerted.
    loud = [f for f in new if not f.get("learning")]
    if loud:
        _alert(agent_id, loud, contained=contained, failed=failed)
    elif contained and waiting:
        # the earlier report said it could not be contained; say that it now is
        _audit("agent_drift_contained", agent_id, findings=[f["key"] for f in waiting])
        _alert(agent_id, waiting, contained=True, failed=False)
    result.update(new_findings=[f["key"] for f in new], contained=contained)
    if failed:
        result["containment_failed"] = True
    return result


def check_all(*, now: float | None = None) -> list[dict]:
    """``check`` every enrolled agent. One agent's failure does not stop the
    rest; it is logged and returned as ``{"agent_id", "error"}``. An
    unreadable record or enrollment sidecar, or an audit log that refuses to
    write, stops the sweep. Returns nothing when drift detection is off."""
    if not enabled():
        return []
    from .audit.errors import AuditRefused
    results = []
    for agent_id in sorted(_enrolled_ids()):
        try:
            results.append(check(agent_id, now=now))
        except (AuditRefused, AgentDriftStoreError):
            raise
        except Exception:
            log.warning("agent_drift: check failed for %r", agent_id, exc_info=True)
            results.append({"agent_id": agent_id,
                            "error": "The drift check for this agent did not finish."})
    return results


def acknowledge(agent_id: str, finding_key: str, *, actor: str,
                now: float | None = None) -> dict:
    """Dismiss one open finding. It stays listed, marked acknowledged, and no
    longer counts toward the agent's state until a new baseline is approved,
    the finding gets more severe, or it goes away for a day and comes back.
    Audited (``agent_drift_acknowledged``). Raises :class:`AgentDriftError`
    when the agent is not enrolled, there is no such open finding, or the
    acknowledgement could not be written to the audit log."""
    who = _actor(actor)
    cfg = settings()
    moment = _now(now)
    with _editing() as agents:
        record = _current_record(agents, agent_id, _enrolled_ids())
        result = _evaluate_record(agent_id, record, cfg, moment, active=_active(cfg))
        finding = next((f for f in result["findings"]
                        if f["key"] == finding_key and not f["acknowledged"]), None)
        if record is None or finding is None:
            raise AgentDriftError(
                f"{agent_id!r} has no open finding {finding_key!r} to acknowledge.")
        if not _audit("agent_drift_acknowledged", agent_id, finding=finding["key"],
                      finding_kind=finding["kind"], severity=finding["severity"],
                      acknowledged_by=who):
            raise AgentDriftError(_NOT_RECORDED)
        acks = _dict(record.get("acknowledged"))
        acks[finding["key"]] = {"by": who, "at": moment, "seen": moment,
                                "severity": finding["severity"]}
        record["acknowledged"] = _newest(acks, "at", _MAX_ACKNOWLEDGED)
    from .ops_alert import incident

    incident("drift", agent_id, cause=finding["key"], resolve=True)
    return {"agent_id": agent_id, "finding": finding["key"],
            "acknowledged_by": who, "acknowledged_at": moment}


def _audit(kind: str, agent_id: str, **payload: Any) -> bool:
    """Write one audit row. A refusal from the audit log propagates, so the
    action it describes is not carried out without its evidence."""
    from .audit import audit_event
    return audit_event(kind, agent="agent_drift", external_agent=agent_id, **payload)


def _new_findings(findings: list[dict], reported: dict) -> list[dict]:
    """Open findings not reported before, or reported at a lower severity."""
    out = []
    for f in findings:
        entry = _dict(reported.get(f["key"]))
        # A finding recorded in the learning period is reported again, once, when it ends.
        if not f["acknowledged"] and (_RANK[f["severity"]] > _rank(entry.get("severity"))
                                      or (entry.get("learning") and not f.get("learning"))):
            out.append(f)
    return out


def _contain(agent_id: str) -> tuple[bool, bool]:
    """Contain the agent at the gateway. Returns ``(contained now, failed)``;
    an agent that is already contained is left as it is."""
    from . import external_agents
    from .audit.errors import AuditRefused
    try:
        if external_agents.containment_state(agent_id):
            return False, False
        landed = external_agents.contain(agent_id, contained_by="drift")
        return landed, not landed
    except AuditRefused:
        raise
    except Exception:
        log.exception("agent_drift: could not contain %r after a high-severity finding",
                      agent_id)
        return False, True


def _report_new(agent_id: str, cfg: dict, moment: float, *, contained: bool,
                failed: bool, seen: set[str]) -> list[dict]:
    """Under the store lock: audit the findings not reported before and
    remember them, so two checks at once report a finding only once.

    Only findings the caller already evaluated (``seen``) are reported now. One
    that appeared since then waits for the next check, so a high finding is
    never remembered without the containment decision having seen it. A
    finding whose audit row could not be written is not remembered either, so
    it is reported again. With ``failed`` (containment failed) high findings
    are remembered as still waiting for containment."""
    with _editing() as agents:
        record = _current_record(agents, agent_id, _enrolled_ids())
        if record is None:
            return []
        result = _evaluate_record(agent_id, record, cfg, moment, active=True)
        reported = _dict(record.get("reported"))
        unreported = _new_findings(result["findings"], reported)
        recorded = []
        for finding in unreported:
            if finding["key"] in seen and _audit(
                    "agent_drift_detected", agent_id, finding=finding["key"],
                    finding_kind=finding["kind"], severity=finding["severity"],
                    baseline=finding["baseline"], current=finding["current"],
                    summary=finding["summary"], reaction=cfg["on_drift"], contained=contained,
                    learning_period=bool(finding.get("learning"))):
                recorded.append(finding)
        hold = {f["key"] for f in unreported} - {f["key"] for f in recorded}
        record["reported"] = _remember(reported, result["findings"], moment,
                                       hold=hold, pending=failed)
        record["acknowledged"] = _live_acknowledgements(
            _dict(record.get("acknowledged")), result["findings"], moment)
    return recorded


def _remember(reported: dict, findings: list[dict], moment: float, *, hold: set[str],
              pending: bool) -> dict:
    """The bounded record of what has been reported, brought up to date.
    Findings in ``hold`` are left out so the next check reports them. With
    ``pending`` a high finding is marked as still waiting for containment."""
    present = {f["key"] for f in findings}
    for finding in findings:
        key = finding["key"]
        if finding["acknowledged"] or key in hold:
            continue
        entry = _dict(reported.get(key))
        if (_RANK[finding["severity"]] > _rank(entry.get("severity"))
                or (entry.get("learning") and not finding.get("learning"))):
            entry = {"at": moment, "seen": moment, "severity": finding["severity"]}
            if finding.get("learning"):
                entry["learning"] = True
            reported[key] = entry
        elif moment - _amount(entry.get("seen")) >= _SEEN_REFRESH_SECONDS:
            entry["seen"] = moment
        if finding["severity"] == HIGH and pending and not finding.get("learning"):
            entry["containment_pending"] = True
        else:
            entry.pop("containment_pending", None)
    for key in [key for key, entry in reported.items() if key not in present
                and moment - _amount(_dict(entry).get("seen")) > _QUIET_SECONDS]:
        del reported[key]
    return _newest(reported, "seen", _MAX_REPORTED)


def _live_acknowledgements(acknowledged: dict, findings: list[dict], moment: float) -> dict:
    """Acknowledgements that still apply. One covers a finding while it lasts;
    once the finding has been gone for a day the acknowledgement is dropped,
    so the same kind of change coming back later is reported afresh."""
    present = {f["key"] for f in findings}
    for key, ack in list(acknowledged.items()):
        ack = _dict(ack)
        last = _amount(ack.get("seen")) or _amount(ack.get("at"))
        if key in present:
            if moment - last >= _SEEN_REFRESH_SECONDS:
                ack["seen"] = moment
                acknowledged[key] = ack
        elif moment - last > _QUIET_SECONDS:
            del acknowledged[key]
    return acknowledged


def _newest(entries: dict, stamp: str, keep: int) -> dict:
    """The ``keep`` entries with the latest ``stamp``."""
    if len(entries) <= keep:
        return entries
    ordered = sorted(entries.items(),
                     key=lambda item: _amount(_dict(item[1]).get(stamp)), reverse=True)
    return dict(ordered[:keep])


def _alert(agent_id: str, new: list[dict], *, contained: bool, failed: bool) -> None:
    """One operator alert for a batch of new findings. Best effort."""
    worst = max(new, key=lambda f: _RANK[f["severity"]])
    text = f"{agent_id} has moved away from its approved baseline. {worst['summary']}"
    if len(new) > 1:
        more = len(new) - 1
        text += f" {_plural(more, 'more finding')} {'needs' if more == 1 else 'need'} review."
    if contained:
        text += " The agent has been contained until someone reviews it."
    elif failed:
        text += " It could not be contained automatically; contain it by hand if needed."
    try:
        from .ops_alert import alert, incident

        for finding in new:
            if finding["severity"] == HIGH:
                incident("drift", agent_id, cause=finding["key"])
        alert("agent_drift.detected", text, severity=_ALERT_SEVERITY[worst["severity"]])
    except Exception:  # pragma: no cover -- notification never blocks
        log.warning("agent_drift: alert delivery failed", exc_info=True)


def roster_view(*, now: float | None = None) -> list[dict]:
    """One row per enrolled agent: ``{agent_id, state, findings_count,
    highest_severity, baseline_approved_at, baseline_approved_by,
    last_observed_at}``. Reads only. An unreadable record or enrollment
    sidecar raises instead of returning a reassuring empty list."""
    cfg = settings()
    moment = _now(now)
    active = _active(cfg)
    agents = _load_store()
    rows = []
    enrolled = _enrolled_ids()
    for agent_id in sorted(enrolled):
        record = _current_record(agents, agent_id, enrolled)
        result = _evaluate_record(agent_id, record, cfg, moment, active=active)
        approved = result["baseline"] or {}
        rows.append({
            "agent_id": agent_id,
            "state": result["state"],
            "findings_count": result["findings_count"],
            "highest_severity": result["highest_severity"],
            "baseline_approved_at": approved.get("approved_at"),
            "baseline_approved_by": approved.get("approved_by", ""),
            "last_observed_at": _dict(record).get("last_observed_at"),
        })
    return rows


def findings_reported_since(since: float, *, now: float | None = None) -> list[dict]:
    """Current findings reported since the given time, from one read of the store."""
    cfg = settings()
    moment = _now(now)
    active = _active(cfg)
    agents = _load_store()
    enrolled = _enrolled_ids()
    rows = []
    for agent_id in sorted(enrolled):
        record = _current_record(agents, agent_id, enrolled)
        for finding in _evaluate_record(agent_id, record, cfg, moment, active=active)["findings"]:
            when = _amount(finding.get("reported_at"))
            if since <= when <= moment and when > 0:
                rows.append({**finding, "agent_id": agent_id, "reported_at": when})
    return sorted(rows, key=lambda row: (-row["reported_at"], row["agent_id"]))


def detail(agent_id: str, *, now: float | None = None) -> dict:
    """One enrolled agent's evaluation (state, findings, baseline, current
    window) plus the configuration last seen and a daily series for charts,
    oldest day first, at most ``_SERIES_DAYS`` long. Reads only."""
    enrolled = _enrolled_ids()
    if agent_id not in enrolled:
        raise AgentDriftError(f"agent {agent_id!r} is not enrolled")
    cfg = settings()
    moment = _now(now)
    record = _dict(_current_record(_load_store(), agent_id, enrolled))
    out = _evaluate_record(agent_id, record, cfg, moment, active=_active(cfg))
    out["config"] = _config_view(_dict(record.get("config")))
    out["last_observed_at"] = record.get("last_observed_at")
    out["series"] = _series(_dict(record.get("days")), _epoch_day(moment))
    return out


def _series(days: dict, today: int) -> list[dict]:
    rows = []
    for epoch_day in range(today - _SERIES_DAYS + 1, today + 1):
        totals = _window(days, epoch_day, epoch_day)
        totals.pop("tools")
        rows.append({"day": _day_key(epoch_day), **totals})
    return rows


__all__ = [
    "AgentDriftError",
    "AgentDriftStoreError",
    "acknowledge",
    "approve_baseline",
    "baseline",
    "change_ratio",
    "check",
    "check_all",
    "detail",
    "enabled",
    "evaluate",
    "js_divergence",
    "observe_discovered",
    "observe_run",
    "observe_screen",
    "roster_view",
    "settings",
    "share",
    "store_path",
]
