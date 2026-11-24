"""Explain the same current role resolution used by dashboard authorization."""
from __future__ import annotations


def role(principal, *, installation=False, without_explicit=False, request=None):
    from maverick.paths import current_tenant_id

    from . import auth, rbac, scim_groups, strict_reads

    if not principal:
        return {"role": None, "source": "Local installation authority", "owner": "Installation administrator"}
    if scim_groups.active_for_principal(principal) is False:
        return {"role": None, "source": "Deactivated identity", "owner": "Identity administrator"}
    if auth.is_dashboard_admin(principal):
        return {"role": "admin", "source": "Pinned installation administrator", "owner": "Installation administrator"}
    tenant = current_tenant_id()
    if tenant and not installation:
        membership = rbac.get_tenant_role(tenant, principal)
        if membership:
            return {"role": membership, "source": "Current workspace membership", "owner": "Workspace administrator"}
    explicit = rbac.get_stored_role(principal) if not without_explicit else None
    if explicit:
        return {"role": explicit, "source": "Explicit installation role", "owner": "Installation administrator"}
    try:
        with strict_reads.strict():
            group = scim_groups.role_for_principal(principal)
    except Exception:
        if strict_reads.active():
            raise
        return {"role": None, "source": "Sign-in group policy unavailable", "owner": "Identity or installation administrator"}
    if group:
        return {"role": group, "source": "Verified sign-in group mapping", "owner": "Identity or installation administrator"}
    from . import sign_in_roles

    claim = sign_in_roles.for_request(request, principal)
    if claim:
        return {"role": claim, "source": "Verified sign-in app role", "owner": "Identity or installation administrator"}
    if rbac.tenant_role_scope_initialized():
        from maverick.paths import tenant_by_user_enabled

        if not installation and tenant_by_user_enabled() and tenant == f"api:{principal}":
            return {"role": rbac.default_role(), "source": "Per-user workspace default", "owner": "Installation administrator"}
        return {"role": None, "source": "No installation role or selected workspace membership", "owner": "Installation administrator"}
    return {"role": rbac.default_role(), "source": "Configured first-login default", "owner": "Installation administrator"}


def denial(request, permission, *, installation=False):
    from . import auth
    from .identity_format import role_label
    try:
        current = role(auth._authorization_principal(request), installation=installation, request=request)
        name = role_label(current["role"]) if current["role"] else "No active role"
        return (f"Your {name} role from {current['source'].lower()} does not allow {permission}. "
                f"Ask your {current['owner'].lower()} to review access. Account shows your current permissions; Permission requests lets you ask the policy owner for review.")
    except Exception:
        return "Your current access policy is unavailable. Ask an installation administrator to restore it before retrying."
