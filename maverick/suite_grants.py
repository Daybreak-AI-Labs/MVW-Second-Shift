"""Per-user department (suite) access grants: job-function scoping (kernel).

The dashboard's privilege RBAC (``maverick_dashboard.rbac``) answers "how MUCH
may this user do?"; this store answers the orthogonal "WHICH part of the
workforce may they use?" — a finance analyst granted ``{"finance", "tax"}``
works with Finance and Tax specialists, never Legal's.

This module is the KERNEL home of the store and its enforcement so that every
caller — the dashboard, the CLI, and any future networked surface — shares one
source of truth (:func:`ensure_suite_allowed` at the deploy/dispatch
chokepoints in :mod:`maverick.departments` and :mod:`maverick.fleet`).
``maverick_dashboard.suite_grants`` re-exports this module for backward
compatibility; the dashboard additionally layers SCIM-group-derived grants on
top at HTTP resolution time (see ``maverick_dashboard.auth.caller_suites``).

Safety invariants:
  * No/empty acting principal (host operator via the CLI, auth-off dashboard)
    -> unrestricted; every gate is a no-op — kernel rule 1, fail open.
  * A configured dashboard admin (``MAVERICK_DASHBOARD_ADMINS`` /
    ``[dashboard] admins``) is never scoped.
  * No stored grant -> unrestricted by default (opt-in scoping);
    ``[dashboard] default_suites`` flips that to deny-by-default.
  * The store is control-plane data: one GLOBAL file, never per-tenant.

Store: ``~/.maverick/dashboard-user-suites.json`` (0600),
``{principal: [suite, ...]}``. An explicit EMPTY list is a valid grant meaning
"no departments at all"; remove the entry to lift scoping.
"""
from __future__ import annotations
import os


def admin_principals() -> frozenset[str]:
    """The configured dashboard admins (never scoped by department grants).

    Mirrors ``maverick_dashboard.auth.is_dashboard_admin`` exactly — the
    ``MAVERICK_DASHBOARD_ADMINS`` env (comma-separated) overrides the
    ``[dashboard] admins`` config list — so the kernel gate and the dashboard
    gate can never disagree about who bypasses scoping."""
    env = (os.environ.get("MAVERICK_DASHBOARD_ADMINS") or "").strip()
    if env:
        return frozenset(a.strip() for a in env.split(",") if a.strip())
    try:
        from .config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            return frozenset()
        dashboard = cfg.get("dashboard", {})
        if dashboard is None:
            dashboard = {}
        if not isinstance(dashboard, dict):
            return frozenset()
        raw = dashboard.get("admins", []) or []
    except Exception:  # malformed policy must never create a bypass principal
        return frozenset()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return frozenset()
    return frozenset(str(a).strip() for a in raw if str(a).strip())


def is_admin_principal(principal: str) -> bool:
    return bool(principal) and principal in admin_principals()


__all__ = [
    "admin_principals",
    "is_admin_principal",
]
