"""Starter rule sets offered when an outside agent is added.

These are starting points chosen by the developers of Second Shift. They
are not policy. They exist so a person does not face an empty form; they fill the
limits on the form, and the person can change any of them before saving. An
administrator should review them against the organisation's own rules before
relying on them.

Each set names the riskiest action the agent may take (``max_risk``), the risk
rating from which a person must approve each action (``approval_at``; an
organisation-wide setting can only make this stricter, never looser), a
spending limit that starts again each month, and how long its access keys last.

This module only holds the definitions and merges them with what the person
chose. It does not enroll anything.
"""
from __future__ import annotations

from typing import Any

#: key -> label, one plain sentence, values. ``approval_at`` of "high" is the
#: organisation-wide default, so the moderate set adds nothing to it.
STARTERS: dict[str, dict[str, Any]] = {
    "customer_facing": {
        "label": "Customer-facing",
        "summary": "Strict. Only low-risk actions, a person approves anything medium or above, "
                   "a small monthly spending limit and access keys that last 30 days.",
        "values": {"max_risk": "low", "approval_at": "medium", "max_dollars": 25.0,
                   "budget_period": "monthly", "expires_days": 30},
    },
    "internal_helper": {
        "label": "Internal helper",
        "summary": "Moderate. Up to medium-risk actions, a person approves high-risk ones, "
                   "a monthly spending limit and access keys that last 90 days.",
        "values": {"max_risk": "medium", "approval_at": "high", "max_dollars": 100.0,
                   "budget_period": "monthly", "expires_days": 90},
    },
    "finance_hr": {
        "label": "Finance or HR data",
        "summary": "Strict. Up to medium-risk actions, and a person approves every action rated "
                   "medium or above, a small monthly spending limit and access keys that last 30 days.",
        "values": {"max_risk": "medium", "approval_at": "medium", "max_dollars": 25.0,
                   "budget_period": "monthly", "expires_days": 30},
    },
}


def values(key: str) -> dict[str, Any] | None:
    """A copy of one starter's limits, or ``None`` for a name that is not one."""
    entry = STARTERS.get(key)
    return dict(entry["values"]) if entry else None


def resolve(key: str, given: dict[str, Any]) -> dict[str, Any]:
    """The starter's limits with every value the person set put over them.

    ``given`` holds only the fields the person actually sent; a field set to
    ``None`` ("no limit") is a choice and wins like any other. Raises
    ``ValueError`` for an unknown starter."""
    base = values(key)
    if base is None:
        raise ValueError(f"unknown starter {key!r}; expected one of {', '.join(sorted(STARTERS))}")
    base.update({k: v for k, v in given.items() if k in base})
    return base
