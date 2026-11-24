"""Employee content authority is distinct from administrator policy authority.

The default is exact ownership. Exceptional reads require a purpose-bound,
independently approved, expiring resource grant with an acknowledged audit.
This does not grant mutation, publishing, or access to another task in a thread.
"""
from __future__ import annotations

import hashlib
import json
import time

from fastapi import HTTPException

from maverick.governed_records import GovernedRecordStore

STORE = GovernedRecordStore("employee_content_access", "ECA", "employee_content_access",
                            authority_scope="deployment_global")


def enabled() -> bool:
    from maverick.config import get_features

    return get_features().get("employee_content_access_requests") is True


def tenant() -> str:
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict() or ""


def _reviewer_current(record: dict) -> bool:
    from . import auth, rbac, scim_groups

    reviewer = record.get("reviewed_by")
    if not reviewer or reviewer == record.get("requester"):
        return False
    if scim_groups.active_for_principal(reviewer) is False:
        return False
    if reviewer == record.get("owner"):
        scope = record.get("tenant")
        role = rbac.get_tenant_role(scope, reviewer) if scope else auth.global_role_for_principal(reviewer)
        return "view" in rbac.permissions_for(role) if role else False
    return "admin" in rbac.permissions_for(auth.global_role_for_principal(reviewer))


def _grant_current(grant: dict, *, owner: str, resource_kind: str, resource_id: str,
                   resource_revision: str | None = None) -> bool:
    """An approved, unexpired, independently reviewed read grant for exactly this resource."""
    return not (grant.get("tenant") != tenant() or grant.get("owner") != owner
                or grant.get("resource_kind") != resource_kind
                or grant.get("resource_id") != str(resource_id)
                or (resource_revision is not None and grant.get("resource_revision") != resource_revision)
                or grant.get("status") != "approved" or grant.get("_audit_pending")
                or grant.get("expires_at", 0) <= time.time() or not _reviewer_current(grant))


def grant_readers(owner: str, *, resource_kind: str, resource_id: str, resource_revision: str | None = None,
                  among=None) -> set[str]:
    """The requesters holding a current, independently reviewed read grant for
    exactly this resource (see :func:`_grant_current`). With ``among``, only
    those people's grants are checked, and nobody's store is read for nobody.
    An unreadable grant store or reviewer check opens nothing (it raises
    inside ``strict_reads.strict()``)."""
    if not enabled() or (among is not None and not among):
        return set()
    readers = set()
    try:
        for grant in STORE.list():
            requester = grant.get("requester")
            if (isinstance(requester, str) and requester and (among is None or requester in among)
                    and _grant_current(grant, owner=owner, resource_kind=resource_kind, resource_id=resource_id,
                                       resource_revision=resource_revision)):
                readers.add(requester)
    except Exception:  # noqa: BLE001 -- an unreadable grant store opens nothing
        from . import strict_reads

        if strict_reads.active():
            raise
        return set()
    return readers


def may_read_employee_content(request, owner: str, *, resource_kind: str, resource_id: str, resource_revision: str | None = None) -> bool:
    from maverick.audit import record as record_audit

    from . import auth, scim_groups

    actor = auth._authorization_principal(request)
    if actor is None:
        # An installation credential identifies no employee. It can still open
        # genuinely unowned local work, but never bypass named-owner privacy.
        return not owner
    if owner and actor == owner:
        return True
    eligible = auth.has_permission(request, "approve") if resource_kind == "approval" else auth.has_global_permission(request, "admin")
    if not enabled() or not eligible:
        return False
    if scim_groups.active_for_principal(actor) is False:
        return False
    try:
        for grant in STORE.list():
            if grant.get("requester") != actor or not _grant_current(
                    grant, owner=owner, resource_kind=resource_kind, resource_id=resource_id,
                    resource_revision=resource_revision):
                continue
            # Every actual exceptional read needs its own confirmed receipt.
            return record_audit("employee_content_read", agent=actor, actor=actor,
                                access_request=grant["id"], purpose=grant["purpose"],
                                resource_kind=resource_kind, resource_id=str(resource_id)) is True
    except Exception:
        return False
    return False


def approval_resource(approval, world) -> dict:
    owner = approval.requested_by or ""
    if approval.goal_id:
        goal = world.get_goal(approval.goal_id)
        if goal is None:
            raise HTTPException(404, "No such approval.")
        owner = goal.owner or ""
    revision = hashlib.sha256(json.dumps([approval.id, owner, approval.goal_id,
        approval.action, approval.scope, approval.detail], sort_keys=True).encode()).hexdigest()
    return {"resource_kind": "approval", "resource_id": str(approval.id), "owner": owner,
            "resource_revision": revision, "label": f"Approval {approval.id} — {approval.status}"}


def _governance_request(approval) -> bool:
    """An outside agent's request, or a request about one (an access key).
    It is a governance record, not one employee's private work."""
    return getattr(approval, "provenance", None) == "external_agents"


def _people_with_a_role() -> set[str]:
    """Everyone given a role here; callers keep those who may decide."""
    from maverick import entra_directory

    from . import rbac

    try:
        # With the Entra directory on, people whose role comes only from an
        # app role count too (nobody when it is off or cannot be read).
        return set(rbac.list_users()) | entra_directory.principals_with_role()
    except Exception:  # noqa: BLE001 -- an unreadable roster names nobody
        return set()


def can_read_approval(request, approval, world=None) -> bool:
    if approval is None:
        return False
    from . import auth
    # Approval cards also appear in Oversight, Action Center and personal
    # notifications. Those projections must honor the same key scope as the
    # queue, even when the card belongs to the key's owner.
    if (auth.api_key_permissions(request) is not None
            and not auth.has_permission(request, "approve", api_scope="approvals:decide")):
        return False
    if _governance_request(approval):
        return auth.has_permission(request, "approve")
    if world is None:
        from ._shared import _world
        world = _world()
    try:
        resource = approval_resource(approval, world)
    except HTTPException:
        return False
    return may_read_employee_content(request, resource["owner"], resource_kind="approval",
        resource_id=resource["resource_id"], resource_revision=resource["resource_revision"])


def approval_readers(approval, world, *, among=None) -> set[str]:
    """The people who can open this approval card on the Approvals page.

    Its owner, plus (while exceptional access is on) anyone holding a current,
    independently reviewed read grant for exactly this card -- the same rules
    :func:`can_read_approval` applies to a reader. An unreadable grant store
    opens nothing, as it would for that reader. ``among`` is as for
    :func:`grant_readers`. An outside agent's request is open to everyone
    given a role (the caller keeps those who may decide)."""
    if _governance_request(approval):
        people = _people_with_a_role()
        return people if among is None else people & set(among)
    try:
        resource = approval_resource(approval, world)
    except HTTPException:
        return set()
    readers = {resource["owner"]} if resource["owner"] else set()
    # The owner's access needs no grant, so it never waits on the grant store.
    return readers | grant_readers(resource["owner"], resource_kind="approval", resource_id=resource["resource_id"],
                                   resource_revision=resource["resource_revision"],
                                   among=None if among is None else set(among) - readers)


def require_approval_content(request, approval_id, world=None):
    if world is None:
        from ._shared import _world
        world = _world()
    row = world.get_approval(int(approval_id))
    if row is None:
        raise HTTPException(404, "No such approval.")
    if not can_read_approval(request, row, world):
        raise HTTPException(403, "This approval contains private employee content. Request its exact approval-card read in Content access; existing decision authority is still required.")
    return row
