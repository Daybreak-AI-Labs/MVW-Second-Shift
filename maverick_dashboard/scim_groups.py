"""Directory-provisioned groups. This product does not receive a user directory feed yet.

No group grants a role, and no account is known to be deprovisioned: sign-in
and roles are decided by the identity provider and the role settings alone.
"""
from __future__ import annotations


def role_for_principal(principal: str) -> str | None:
    return None


def active_for_principal(principal: str) -> bool | None:
    """None: the directory has no record of this account either way."""
    return None
