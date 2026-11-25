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

import logging
import time

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

log = logging.getLogger(__name__)

# The routes and their tests reach the shared functions through these names.
_audit_approval_decision = audit_approval_decision
_safe_action_label = safe_action_label


class ApprovalDecisionRefused(ChannelApprovalRefused):
    """A vote from a chat app was not accepted; ``detail`` is a plain sentence
    for the person."""

    def __init__(self, detail: str, *, status_code: int = 409, reason: str = "refused") -> None:
        super().__init__(reason, detail, status_code=status_code)


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
    """Holds ``approve`` in this workspace and is not deprovisioned."""
    from . import rbac, scim_groups
    from .auth import role_for_principal

    try:
        if "approve" not in rbac.permissions_for(role_for_principal(principal, directory=True)):
            return False
        return scim_groups.active_for_principal(principal) is not False
    except Exception:  # an unreadable roster lets nobody decide, so nobody counts
        return False


def _chat_approvers(approval) -> set[str]:
    """People linked in a chat app where this request's card is posted.

    Slack posts every card to its approvals channel; protected-settings
    requests are decided in the dashboard only. Teams is not counted here: its
    cards go only to people who can already open the request, so they are
    already among the readers."""
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
    return {person for person in people if person}


def eligible_approvers(world, approval) -> set[str]:
    """Everyone who could decide ``approval`` now, by the rules each surface
    already enforces.

    On the Approvals page: people holding ``approve`` in this workspace who
    can open the request -- its owner, or a current, reviewed read grant for
    exactly this card (:func:`content_access.approval_readers`). In Slack or
    Teams, where its card is posted: linked people holding ``approve``. A
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


# ----------------------------------------------------------------- channels


def _audit_channel_denial(principal: str, *, channel: str, approval_id: int, reason: str) -> None:
    """Record a refused chat decision the way ``require_approval_authority``
    records a refused one on the web page."""
    from maverick import audit
    from maverick.approval_cards import digest
    from maverick.paths import current_tenant_id_strict

    audit.audit_event(
        audit.EventKind.CAPABILITY_DENIED,
        agent=principal,
        action="approval.decide",
        principal=principal,
        channel=channel,
        tenant=current_tenant_id_strict() or "",
        resource_sha256=digest({"kind": "approval", "resource": str(approval_id)}),
        reason=reason,
    )


def _refuse(principal: str, channel: str, approval_id: int, reason: str, detail: str, *,
            status_code: int = 403) -> ApprovalDecisionRefused:
    try:
        _audit_channel_denial(principal, channel=channel, approval_id=approval_id, reason=reason)
    except Exception:  # noqa: BLE001 -- the refusal stands even if its record cannot be written
        log.warning("approval refusal could not be audited", exc_info=True)
    return ApprovalDecisionRefused(detail, status_code=status_code, reason="not_permitted")


def _channel_authority(world, principal: str, *, channel: str, approval_id: int) -> None:
    """The person a chat account is linked to may decide this request on the
    web page, so they may decide it here: they hold ``approve``, are not
    deprovisioned, can open the request (its owner, a reviewed read grant, or
    an outside agent's request, which any role holder can open) and nobody
    else has claimed it. A role that cannot be read refuses."""
    from . import rbac, scim_groups
    from .auth import role_for_principal
    from .content_access import approval_readers

    try:
        permitted = ("approve" in rbac.permissions_for(role_for_principal(principal, directory=True))
                     and scim_groups.active_for_principal(principal) is not False)
        approval = world.get_approval(int(approval_id))
        readable = approval is not None and principal in approval_readers(approval, world)
    except Exception as exc:  # noqa: BLE001 -- what cannot be read cannot be allowed
        log.warning("approval authority could not be checked for %s", channel, exc_info=True)
        raise ApprovalDecisionRefused(
            "Second Shift could not check whether you may decide this request. Open the "
            "Approvals page, or try again in a minute.", status_code=503, reason="not_permitted",
        ) from exc
    if not permitted:
        raise _refuse(principal, channel, approval_id, "approval_authority_missing",
                      "Your Second Shift account can't decide approvals. Ask an administrator "
                      "for the approver role.")
    if approval is None or approval.status != "pending":
        return  # the decision path answers "already decided"
    if not readable:
        raise _refuse(principal, channel, approval_id, "approval_content_unreadable",
                      "Your Second Shift account can't open this request. Ask an administrator "
                      "for access to it.")
    if approval.claimed_by and approval.claimed_by != principal:
        raise ApprovalDecisionRefused(
            "Another reviewer holds this request. Ask them to release it before you decide.",
            status_code=409, reason="claimed")


def decide_from_channel(*, approval_id: int, status: str, principal: str, binding: str,
                        channel: str, channel_user: str = "", acknowledgement: dict | None = None,
                        world=None) -> dict:
    """Record a vote that arrived through a chat app, by the same rules as the
    Approvals page.

    ``status`` is ``"approved"`` or ``"denied"``; ``principal`` is the Second
    Shift user the chat account is tied to. The person needs ``approve`` and
    access to the request, a request protected by a settings change is decided
    on the web only, an approval must name the exact card the person saw
    (``binding``), the person who asked may have to leave a high-risk request
    to someone else, and a high or critical risk approval needs the
    acknowledgement (``{"acknowledged": True, "confirmation": "approve"}``, the
    typed word only for critical risk). The vote goes through the same audited
    outbox as the page's.

    Returns ``{"status", "effective", "decided_by", "decided_at", "risk", "audit",
    "approvals_required", "approved_count", ...}``. Raises
    :class:`ApprovalDecisionRefused` with a plain sentence when nothing was
    recorded."""
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail

    from ._shared import _world
    from .approval_queue_operations import guard

    if status not in ("approved", "denied"):
        raise ApprovalDecisionRefused("Choose approve or reject.", status_code=422, reason="invalid")
    world = world if world is not None else _world()
    who = " ".join(str(principal or "").split())
    if not who:
        raise ApprovalDecisionRefused(
            "Your Teams account isn't linked to a Second Shift user yet.", status_code=403,
            reason="unlinked")
    approval_id = int(approval_id)
    approving = status == "approved"
    try:
        _channel_authority(world, who, channel=channel, approval_id=approval_id)
        approval = world.get_approval(approval_id)
        if approval is None or approval.status != "pending":
            raise ApprovalDecisionRefused(
                "This request was already decided or no longer exists.", status_code=404,
                reason="not_pending")
        if approval.provenance == SETTINGS_PROVENANCE:
            raise ApprovalDecisionRefused(
                "Changes to protected settings are decided on the Second Shift Approvals page, "
                "not in Teams.", status_code=403, reason="dashboard_only")
        vote_guard = None
        if world.get_approval_audit_event(world.approval_audit_event_id(approval_id, status, who)) is None:
            vote_guard = guard(world, approval, who, status, binding, bind_state=False)
        if approving:
            require_current_card(approval, binding=binding)
            try:
                card = decode_approval_detail(approval.detail)
            except ApprovalCardError:
                card = None
            if card and card.get("display"):
                raise ApprovalDecisionRefused(
                    "Review and approve the full operation on the Second Shift Approvals page.",
                    status_code=403, reason="dashboard_only")
            require_separate_approver(world, approval_id, who)
            ack = acknowledgement if isinstance(acknowledgement, dict) else {}
            require_acknowledgement(
                approval, who=who, channel=channel, decision="approved", confirmed=True,
                acknowledged=ack.get("acknowledged") is True,
                typed_confirmation=str(ack.get("confirmation") or ""))
        options = {"reviewed_card": vote_guard} if vote_guard is not None else {}
        event = record_vote(world, approval_id, status, who, **options)
        delivered = audit_approval_decision(world, event)
    except ChannelApprovalRefused as exc:
        raise (exc if isinstance(exc, ApprovalDecisionRefused) else
               ApprovalDecisionRefused(exc.message, status_code=exc.status_code, reason=exc.reason)) from exc
    except HTTPException as exc:  # the queue's own guard answers in HTTP terms
        raise ApprovalDecisionRefused(str(exc.detail), status_code=exc.status_code) from exc
    try:
        state = world.approval_state(approval_id) or {}
    except Exception:  # noqa: BLE001 -- the vote is durable; the read is diagnostic
        state = {}
    final = str(state.get("status") or "pending")
    effective = bool(delivered and final != "pending")
    try:
        from maverick import audit

        audit.audit_event(
            audit.EventKind.CONSENT_RESULT, agent=who, actor=who, action="approval_decided_via_channel",
            approval_id=approval_id, decision=status, channel=channel,
            channel_user=str(channel_user or ""), decided_by=who, effective=effective,
            decision_id=event.event_id)
    except Exception:  # noqa: BLE001 -- the signed decision above is the authority
        log.warning("channel approval audit note failed", exc_info=True)
    return {
        "approval_id": approval_id, "decision": status, "status": final, "effective": effective,
        "decided_by": who, "channel": channel, "risk": str(approval.risk),
        "audit": "delivered" if delivered else "pending",
        "approvals_required": int(state.get("approvals_required") or 1),
        "approved_count": int(state.get("approved_count") or 0),
        "decision_id": event.event_id, "decided_at": time.time(),
    }


def channel_approvers(world, approval, *, among=None) -> set[str]:
    """Who a chat app may show this request to and take a decision from: the
    people who can open it on the Approvals page and hold ``approve`` now."""
    from .content_access import approval_readers

    return {person for person in approval_readers(approval, world, among=among) if _may_decide(person)}


def approval_view(approval_id: int, *, world=None) -> dict | None:
    """The queue row as a chat card needs it: redacted labels, the decoded
    card, its source. ``None`` when the approval does not exist. ``card`` is
    ``None`` for a legacy, corrupted or expired request, which a chat app must
    not offer to approve (the page disables its Approve button the same way)."""
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail
    from maverick.safety.secret_detector import redact

    from ._shared import _world

    world = world if world is not None else _world()
    approval = world.get_approval(int(approval_id))
    if approval is None:
        return None

    def safe(value: object, *, fallback: str = "") -> str:
        try:
            text, _matches = redact(" ".join(str(value or "").split()))
            return text[:2000]
        except Exception:  # noqa: BLE001 -- the fallback is a plain label
            return fallback

    card = None
    card_status = "legacy"
    detail = safe(approval.detail)
    try:
        card = decode_approval_detail(approval.detail)
    except ApprovalCardError:
        detail = "Structured approval details failed their integrity check."
        card_status = "invalid"
    if card is not None:
        card_status = "expired" if time.time() >= card["expires_at"] else "current"
        if card_status == "expired":
            card = None
            detail = "This request's decide-by time has passed. Reject it and ask for a new request."
        else:
            detail = card["summary"]
    try:
        from .app import _approval_source

        source = _approval_source(approval.provenance)
    except Exception:  # noqa: BLE001 -- the label is decoration, never authority
        source = None
    return {
        "approval": {
            "id": approval.id,
            "action": safe(approval.action, fallback="reviewed operation"),
            "risk": str(approval.risk),
            "scope": safe(approval.scope, fallback="reviewed target"),
            "detail": detail,
            "status": approval.status,
            "provenance": approval.provenance,
            "requested_by": approval.requested_by,
            "decided_by": approval.decided_by,
            "decided_at": approval.decided_at,
        },
        "card": card,
        "card_status": card_status,
        "source_label": source,
    }


__all__ = [
    "ApprovalDecisionRefused",
    "approval_view",
    "channel_approvers",
    "decide_from_channel",
    "eligible_approvers",
    "other_eligible_approvers",
    "own_request_note",
    "require_current_decision_card",
]
