"""Tenant markers for the world model's raw, SQLite-paramstyle reads.

``WorldModel.tenant_query`` (and its Postgres mirror) takes SQL that names its
tenant boundary with markers instead of hand-written predicates:

* ``{tenant:COL}`` -- the backend's normal read scope on a root table's tenant
  column (``goals``, ``approvals``, ``conversations``, ...).
* ``{tenant_exact:COL}`` -- the exact scope: legacy rows without a tenant are
  not visible to a bound tenant.
* ``{tenant_goal:COL}`` -- a child row (episodes, turns, questions, ...) whose
  ``COL`` is a goal id in the active tenant.

The SQLite store is one file per tenant, so every marker becomes ``1=1`` there;
the Postgres store substitutes its tenant predicate. Expansion keeps the
positional ``?`` parameters in order.
"""
from __future__ import annotations


class TenantScopeRequired(PermissionError):
    """An unscoped raw read was refused because the store is tenant-scoped."""
