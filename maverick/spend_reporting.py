"""Summarize completed outside-agent run costs and forecast budget usage."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from math import isfinite

from . import external_agents
from .safety.secret_detector import redact

_HISTORY_MONTHS = 12
_DAY_SECONDS = 86400


def _month(moment: datetime, offset: int = 0) -> datetime:
    year, month = divmod(moment.year * 12 + moment.month - 1 + offset, 12)
    return datetime(year, month + 1, 1, tzinfo=UTC)


def _label(value: object, default: str) -> str:
    text, _ = redact(" ".join(str(value or "").split()))
    return text[:200] or default


def _amount(value: object) -> float:
    dollars = float(value)
    if not isfinite(dollars):
        raise ValueError("A recorded cost could not be read.")
    return dollars


def _rows(totals: dict[str, tuple[float, int]], *, monthly: bool = False) -> list[dict]:
    keys = sorted(totals, reverse=True) if monthly else sorted(totals, key=lambda label: (-totals[label][0], label))
    return [{"label": label, "dollars": round(totals[label][0], 4), "runs": totals[label][1]} for label in keys]


def _budget(row: dict, month_cost: float, elapsed_days: float, remaining_days: float) -> dict:
    spent = _amount(row["period_spent"])
    limit = _amount(row["max_dollars"]) if row["max_dollars"] is not None else None
    projection = spent + month_cost / max(elapsed_days, 1.0) * remaining_days
    return {
        "label": _label(row["id"], "Unassigned agent"),
        "budget_period": "Monthly" if row["period"] == "monthly" else "Cumulative",
        "spent_dollars": round(spent, 4),
        "limit_dollars": limit,
        "projected_dollars": round(projection, 4) if limit is not None else None,
        "over_limit": limit is not None and spent > limit,
        "projected_over_limit": limit is not None and projection > limit,
    }


def report(world, *, now: datetime | None = None) -> dict:
    """One twelve-month report, with limits from the current budget meters."""
    moment = datetime.now(UTC) if now is None else now.astimezone(UTC)
    start, end = _month(moment), _month(moment, 1)
    since = _month(moment, 1 - _HISTORY_MONTHS)
    current_month = start.strftime("%Y-%m")
    elapsed = (moment - start).total_seconds() / _DAY_SECONDS
    remaining = (end - moment).total_seconds() / _DAY_SECONDS
    roster = {row["id"]: row for row in external_agents.roster()}
    totals: dict[str, dict[str, tuple[float, int]]] = {
        group: defaultdict(lambda: (0.0, 0)) for group in ("agents", "departments", "platforms", "months")
    }
    for offset in range(1 - _HISTORY_MONTHS, 1):
        totals["months"][_month(moment, offset).strftime("%Y-%m")] = (0.0, 0)
    current: dict[str, float] = defaultdict(float)
    for row in world.agent_spend_groups(since=since.timestamp(), until=moment.timestamp()):
        agent_id = row.owner.removeprefix("agent:")
        dollars = _amount(row.dollars)
        if row.month == current_month:
            current[agent_id] += dollars
        labels = {
            "agents": _label(agent_id, "Unassigned agent"),
            "departments": _label(row.department, "Unassigned"),
            "platforms": _label(roster.get(agent_id, {}).get("platform_label"), "Unknown platform"),
            "months": row.month,
        }
        for group, label in labels.items():
            saved_cost, saved_count = totals[group][label]
            totals[group][label] = saved_cost + dollars, saved_count + row.runs
    budgets = [_budget(row, current[row["id"]], elapsed, remaining) for row in roster.values()]
    budgets.sort(key=lambda row: (not row["over_limit"], not row["projected_over_limit"], row["label"]))
    return {
        "from_month": since.strftime("%Y-%m"),
        "through_month": current_month,
        "total_dollars": round(sum(dollars for dollars, _ in totals["months"].values()), 4),
        **{key: _rows(values, monthly=key == "months") for key, values in totals.items()},
        "budgets": budgets,
    }
