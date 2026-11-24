"""Access-checked queue reviews and exact native vote receipts for Copilot."""
from __future__ import annotations

from fastapi import HTTPException

from maverick.approval_cards import digest
from maverick.approval_vote_review import approval_review_identity


def identity(row) -> str:
    # All queued material and ownership are private commitments. Normal vote
    # state may change after acceptance; a changed card or undo round may not.
    return approval_review_identity(row)


def revision(world, row, who: str) -> str:
    return digest({"identity": identity(row), "state": world.approval_state(row.id),
                   "content_owner": content_owner(world, row),
                   "approve_event": world.approval_audit_event_id(row.id, "approved", who),
                   "deny_event": world.approval_audit_event_id(row.id, "denied", who), "actor": who})


def content_owner(world, row) -> str:
    if not row.goal_id:
        return row.requested_by or ""
    goal = world.get_goal(row.goal_id)
    if goal is None:
        raise HTTPException(409, "The request's original task is unavailable. Read its current status before deciding.")
    return goal.owner or ""


def guard(world, row, who: str, status: str, binding: str, *, bind_state: bool = True) -> dict:
    # The direct queue sends a card binding, not a quorum snapshot. Its native
    # voter checks quorum atomically; don't make a diagnostic state read a new
    # prerequisite for that existing route. Copilot seals its reviewed state.
    return {"actor": who, "approval_id": row.id, "status": status,
            "identity": identity(row), "revision": revision(world, row, who) if bind_state else "",
            "event_id": world.approval_audit_event_id(row.id, status, who),
            "content_owner": content_owner(world, row),
            "binding": binding, "state": world.approval_state(row.id) if bind_state else None}
