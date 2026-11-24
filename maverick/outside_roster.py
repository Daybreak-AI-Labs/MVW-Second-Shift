"""The Outside agents roster: every agent at one of three levels.

* **Watched**: a platform check found it on its platform, nobody added it to
  Second Shift, so it works outside the rules.
* **Added**: enrolled, but Second Shift has not heard from it yet (no
  screening call and no run report).
* **Connected**: enrolled, and it has called Second Shift at least once.

This module only joins what other modules already record (the enrollment
roster and the platform check's list of agents nobody added) into one list,
counts and filters it, and answers the small "has it called yet" question the
guided connect path polls. It enrolls nothing and calls no platform.
"""
from __future__ import annotations

from typing import Any

from . import external_agents as xa

LEVELS = ("watched", "added", "connected")
LEVEL_LABELS = {"watched": "Watched", "added": "Added", "connected": "Connected"}

#: A platform check's name to the platform an agent found there is added as.
CHECK_PLATFORMS = {"foundry": "foundry", "copilot_studio": "copilot",
                   "servicenow": "servicenow", "workday": "workday"}


def _heard_at(row: dict) -> float | None:
    """When Second Shift last heard from an enrolled agent, or ``None``."""
    stamps = [row.get("last_seen"), row.get("last_run_at")]
    good = [float(s) for s in stamps if isinstance(s, (int, float)) and not isinstance(s, bool)]
    return max(good) if good else None


def level_of(row: dict) -> str:
    """The level of one enrolled agent's roster row."""
    return "connected" if _heard_at(row) is not None or int(row.get("runs") or 0) > 0 else "added"


def _received(row: dict) -> str | None:
    """What the agent's last contact was, in words, or ``None`` before any."""
    if level_of(row) != "connected":
        return None
    kind = row.get("last_seen_kind")
    if kind in xa.HEARD_KINDS:
        return xa.HEARD_KINDS[kind]
    return "a run report" if row.get("last_run_at") or row.get("runs") else "a call"


def _enrolled_row(row: dict) -> dict:
    level = level_of(row)
    name = row.get("description") or row["id"]
    return {**row, "level": level, "level_label": LEVEL_LABELS[level], "name": name,
            "platform_key": row["platform"], "heard_at": _heard_at(row), "received": _received(row)}


def _watched_row(entry: dict) -> dict:
    key = CHECK_PLATFORMS.get(str(entry.get("platform")), str(entry.get("platform") or "custom"))
    label = xa.PLATFORMS.get(key) or str(entry.get("platform") or "").replace("_", " ").capitalize()
    return {"id": None, "level": "watched", "level_label": LEVEL_LABELS["watched"],
            "name": entry.get("name") or entry.get("external_id") or "", "platform_key": key,
            "platform_label": label, "state": entry.get("state") or "",
            "external_ref": entry.get("external_ref") or "",
            "first_seen_at": entry.get("first_seen_at"), "last_seen_at": entry.get("last_seen_at"),
            "add_as": CHECK_PLATFORMS.get(str(entry.get("platform")), "")}


def build(agents: list[dict], found: list[dict], *, level: str | None = None,
          platform: str | None = None) -> dict[str, Any]:
    """The roster as ``{"rows", "counts", "platforms"}``.

    ``agents`` is :func:`external_agents.roster`; ``found`` is the platform
    check's agents nobody added. ``counts`` and ``platforms`` always describe
    the whole roster; ``level`` and ``platform`` (ignored when not one of the
    listed values) narrow only ``rows``. Rows are Connected first, then Added,
    then Watched, by name."""
    rows = [_enrolled_row(a) for a in agents] + [_watched_row(f) for f in found]
    order = {"connected": 0, "added": 1, "watched": 2}
    rows.sort(key=lambda r: (order[r["level"]], str(r["name"]).casefold(), str(r["id"] or r["external_ref"])))
    counts = {name: sum(1 for r in rows if r["level"] == name) for name in LEVELS}
    counts["total"] = len(rows)
    keys = sorted({r["platform_key"] for r in rows})
    platforms = [{"key": k, "label": xa.PLATFORMS.get(k) or k.replace("_", " ").capitalize()} for k in keys]
    shown = [r for r in rows
             if (level not in LEVELS or r["level"] == level)
             and (platform not in keys or r["platform_key"] == platform)]
    return {"rows": shown, "counts": counts, "platforms": platforms}


def connection(agent_id: str) -> dict | None:
    """Level, last-heard time and what was received for one enrolled agent,
    or ``None`` when it is not enrolled. Nothing else about the agent."""
    for row in xa.roster():
        if row["id"] == agent_id:
            built = _enrolled_row(row)
            return {"id": agent_id, "level": built["level"], "last_heard_at": built["heard_at"],
                    "received": built["received"]}
    return None
