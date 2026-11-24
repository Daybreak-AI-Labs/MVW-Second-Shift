"""The dashboard's layer over the shared approval decision path.

The primitives (card check, acknowledgement rule, audited vote with undo
rounds, signed audit delivery, undo) live in :mod:`maverick.channel_approvals`
so the Approvals page, the Microsoft Teams cards and the Slack cards share ONE
implementation. This module adds only what the dashboard owns: the HTTP
error mapping the ``/api/v1/approvals/{id}/approve|deny|undo`` routes answer
with, the role check for a chat vote (the linked person needs ``operate``,
like a dashboard voter), the "send back for changes" form of a denial, the
queue-row projection the Teams cards render, and who else could decide a
request (:func:`eligible_approvers`), which the shared separate-approver rule
asks before the person who asked may approve their own high-risk request.
"""
from __future__ import annotations

from fastapi import HTTPException

from maverick.channel_approvals import (
    SETTINGS_PROVENANCE,
    ChannelApprovalRefused,
    audit_approval_decision,
    record_vote,
    require_acknowledgement,
    require_current_card,
    require_separate_approver,
    safe_action_label,
    separate_approver_refusal,
)

# The routes and their tests reach the shared functions through these names.
_audit_approval_decision = audit_approval_decision
_safe_action_label = safe_action_label


CODE_KEY_REFUSED = ("A person must approve a code change on the Approvals page. A key or an "
                    "automation cannot approve one.")
CODE_COPILOT_REFUSED = "Approve a protected code change yourself on the Approvals page."


def require_code_decider(request, approval, *, approving: bool, copilot: bool) -> None:
    """A code change is approved by a person, never by an API key (an
    automation); a protected one also never through Copilot."""
    if not approving or approval is None or approval.action != "codebase_merge":
        return
    from maverick.channel_approvals import CODE_PROTECTED_PROVENANCE

    from . import auth

    if auth.api_key_permissions(request) is not None:
        raise HTTPException(status_code=403, detail=CODE_KEY_REFUSED)
    if copilot and approval.provenance == CODE_PROTECTED_PROVENANCE:
        raise HTTPException(status_code=403, detail=CODE_COPILOT_REFUSED)


def require_current_decision_card(world, approval_id: int, binding: str) -> None:
    """Reject a stale card, expired card, or corrupted structured approval (409)."""
    approval = world.get_approval(approval_id)
    if approval is None or approval.status != "pending":
        return
    try:
        require_current_card(approval, binding=binding)
    except ChannelApprovalRefused as exc:
        raise HTTPException(status_code=409, detail=exc.message) from exc


def _require_separate_approver(world, approval_id: int, who: str) -> None:
    """The person who asked may have to leave a high-risk approval to someone
    else (403 with the plain reason), checked before any confirmation is
    recorded. The shared vote checks it again."""
    try:
        require_separate_approver(world, approval_id, who)
    except ChannelApprovalRefused as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def _require_acknowledgement(world, approval_id: int, payload: dict, who: str, *,
                             channel: str = "dashboard") -> None:
    """High and critical risk approvals need an explicit acknowledgement.

    The Approvals page collects it in its confirmation step; API callers send
    ``{"acknowledged": true}`` and, for critical risk, ``"confirmation":
    "approve"`` typed by the person; the Teams confirm card sends the same
    payload. Off via ``[approval] require_acknowledgement = false``. The outcome
    is written to the audit log as ``approval_confirmation`` with the channel.
    """
    approval = world.get_approval(approval_id)
    if approval is None or approval.status != "pending":
        return
    payload = payload if isinstance(payload, dict) else {}
    try:
        require_acknowledgement(
            approval, who=who, channel=channel, decision="approved", confirmed=True,
            acknowledged=payload.get("acknowledged") is True,
            typed_confirmation=str(payload.get("confirmation") or ""),
        )
    except ChannelApprovalRefused as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def _record_vote_or_raise(world, approval_id: int, status: str, who: str, *,
                          reviewed_card: dict | None = None, effect_guard=None):
    """Apply one approver's vote, mapping a refusal to the right HTTP error.

    Segregation-of-duties refusals are 403, an unknown/already-decided approval
    404, a final decision awaiting signed audit delivery 409; the two
    commit-reconciliation outcomes keep their stable decision id in the
    response so a retry is keyed exactly."""
    try:
        options = {"effect_guard": effect_guard} if effect_guard is not None else {}
        if reviewed_card is not None:
            options["reviewed_card"] = reviewed_card
        return record_vote(world, approval_id, status, who, **options)
    except ChannelApprovalRefused as exc:
        if exc.reason in ("outcome_uncertain", "outbox_integrity_error"):
            state = "uncertain" if exc.reason == "outcome_uncertain" else "integrity_error"
            headers = {
                "X-Second-Shift-Decision-Id": exc.decision_id or "",
                "X-Second-Shift-Approval-State": state,
            }
            if exc.retry_safe:
                headers["Retry-After"] = "1"
            raise HTTPException(
                status_code=exc.status_code,
                detail={
                    "decision": exc.reason,
                    "decision_id": exc.decision_id,
                    "retry_safe": bool(exc.retry_safe),
                },
                headers=headers,
            ) from exc
        if exc.reason == "not_pending":
            raise HTTPException(status_code=404, detail="no such pending approval") from exc
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def _may_decide(principal: str) -> bool:
    """Holds ``operate`` in this workspace and is not deprovisioned."""
    from . import rbac, scim_groups
    from .auth import role_for_principal

    try:
        if "operate" not in rbac.permissions_for(role_for_principal(principal)):
            return False
        return scim_groups.active_for_principal(principal) is not False
    except Exception:  # an unreadable roster lets nobody decide, so nobody counts
        return False


def _chat_approvers(approval) -> set[str]:
    """People linked in a chat app where this request's card is posted.

    Slack posts every card to its approvals channel and Teams to each linked
    approver; protected-settings requests are decided in the dashboard only.
    With company sign-in (OIDC) a chat decision is resolved through the sign-in
    bridge instead of these links, so nobody is counted from them."""
    if getattr(approval, "provenance", None) == SETTINGS_PROVENANCE:
        return set()
    try:
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            return set()
    except Exception:  # unreadable sign-in settings count nobody from chat
        return set()
    people: set[str] = set()
    try:
        from maverick.channel_approvals import slack_announcements_configured

        if slack_announcements_configured():
            from maverick.channel_identities import all_links

            people.update(principal for principal, links in all_links().items()
                          if any(link.get("channel") == "slack" for link in links))
    except Exception:  # an unreadable link store adds nobody
        pass
    try:
        from maverick.approval_notify import teams_approvals_enabled

        if teams_approvals_enabled():
            from maverick.teams_identity import approver_links

            people.update(str(link.get("principal") or "") for link in approver_links())
    except Exception:  # an unreadable link store adds nobody
        pass
    return {person for person in people if person}


def eligible_approvers(world, approval) -> set[str]:
    """Everyone who could decide ``approval`` now, by the rules each surface
    already enforces.

    On the Approvals page: people holding ``operate`` in this workspace who
    can open the request -- its owner, or a current, reviewed read grant for
    exactly this card (:func:`content_access.approval_readers`). In Slack or
    Teams, where its card is posted: linked people holding ``operate``. A
    deprovisioned person never counts. Nobody here is invented: no new role,
    and a store that can't be read adds nobody."""
    from .content_access import approval_readers

    candidates = approval_readers(approval, world) | _chat_approvers(approval)
    return {person for person in candidates if _may_decide(person)}


def other_eligible_approvers(world, approval, requester: str) -> list[str]:
    """The eligible approvers other than ``requester``, sorted."""
    who = " ".join(str(requester or "").split())
    return sorted(person for person in eligible_approvers(world, approval) if person != who)


def own_request_note(world, approval, viewer: str) -> str:
    """What the person who asked is told when their approval can't settle it.

    ``""`` for anyone else, or when the requester may approve. With one
    approver, the separate-approver rule (``[approval] separate_approver``);
    with two or more, the requester's vote counts only when ``[security]
    allow_self_approval`` is on."""
    who = " ".join(str(viewer or "").split())
    if not who or who != " ".join(str(getattr(approval, "requested_by", "") or "").split()):
        return ""
    if max(1, int(getattr(approval, "approvals_required", 1) or 1)) > 1:
        from maverick.safety.dual_control import allow_self_approval

        return "" if allow_self_approval() else "You asked for this, so other people must approve it."
    return separate_approver_refusal(world, approval, who)


__all__ = [
    "eligible_approvers",
    "other_eligible_approvers",
    "own_request_note",
    "require_current_decision_card",
]
