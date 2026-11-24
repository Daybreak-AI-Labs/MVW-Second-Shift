"""Guided opt-in for Postgres Row-Level Security (RLS).

Enabling RLS (``[world_model] rls = true`` / ``MAVERICK_PG_RLS=1``) makes the
database itself enforce the tenant boundary -- defense in depth over the
app-layer ``_tenant_scope`` predicate. But the policy is strict, fail-closed
equality: a row is visible/writable only when its ``tenant_id`` equals the active
tenant (``postgres._rls_policy_sql``). That has two sharp edges, so RLS must not
be flipped on blindly:

  - **Legacy unscoped rows vanish.** Pre-tenancy rows carry ``tenant_id IS NULL``
    (the event inbox and receipts use the empty string);
    ``NULL = <tenant>`` is never true, so once RLS is *forced* those rows become
    invisible **and** frozen (they also fail the ``WITH CHECK``).
  - **Only the table owner may install the policy.** ``_apply_rls`` runs
    ``ALTER TABLE ... ENABLE/FORCE ROW LEVEL SECURITY`` + ``CREATE POLICY``;
    a non-owner connection raises at startup instead.

This module is the safe on-ramp run *before* enabling RLS:

  - :func:`preflight` reports, per tenant-scoped table, whether the current role
    owns it (can install the policy) and how many legacy unscoped rows remain.
  - :func:`backfill` assigns those rows to a chosen tenant so RLS scopes
    them to that tenant instead of hiding them. Idempotent.

Exposed as ``maverick tenant rls-preflight`` and ``maverick tenant backfill``.

Table names come from the fixed :data:`_PREFLIGHT_TABLES` allow-set -- never
user input -- so the f-string interpolation here is injection-free (same
discipline as the rest of the backend); the tenant id is always a bound param.
"""
from __future__ import annotations

from typing import Any

from .postgres import _RLS_CHILD_TABLES, _RLS_STAMPED_TABLES, _RLS_TABLES, _RLS_TENANT_COLUMN

_EMPTY_TENANT_TABLES = ("event_goal_admissions", "event_trigger_batches")
# Unbound writers stamp the empty string, not NULL, in these tables (the event
# inbox and receipts, and the workspace-keyed webhook/deadline tables).
_EMPTY_SCOPE_TABLES = (*_EMPTY_TENANT_TABLES, *_RLS_TENANT_COLUMN)
# Every table the RLS policy is forced on, so nothing it would hide goes
# unreported or un-backfilled. ``encryption_migrations`` is excluded: its scope
# key is derived from the tenant and is managed by the backend itself. So are
# events and episodes: their tenant is a copy of their goal's, and follows it.
_PREFLIGHT_TABLES = tuple(t for t in _RLS_TABLES
                          if t != "encryption_migrations" and t not in _RLS_STAMPED_TABLES)


def _column(table: str) -> str:
    return _RLS_TENANT_COLUMN.get(table, "tenant_id")
#: How long a count that lifts FORCE waits for the table. ALTER TABLE queues
#: for an exclusive lock, and every later query on the table waits behind it,
#: so the wait is kept short; a busy table is reported, not waited for.
_COUNT_LOCK_TIMEOUT_MS = 200
#: The child tables :func:`preflight` checks for rows with no parent, which no
#: workspace can see once row-level security is on: ``(table, parent, key)``.
_ORPHAN_CHECKS = tuple((t, parent, key) for t, (parent, key) in sorted(_RLS_CHILD_TABLES.items()))


def _visibility(bypass: bool, role: str, catalog: tuple) -> str | None:
    """How ``role`` can see every row of a table: a :data:`COUNT_METHODS`
    key, or ``None`` when the policy applies to it and it cannot lift it."""
    owner, rls_on, forced = catalog
    if bypass:
        return "bypass"
    if not rls_on:
        return "no_policy"
    if owner == role:
        return "owner_no_force" if forced else "owner"
    return None


def _catalog(cur, table: str) -> tuple:
    cur.execute(
        "SELECT pg_get_userbyid(relowner), relrowsecurity, relforcerowsecurity "
        "FROM pg_class WHERE oid = %s::regclass",
        (table,),
    )
    owner, rls_on, forced = cur.fetchone()
    return owner, bool(rls_on), bool(forced)


def _count_legacy(cur, table: str) -> tuple[int, int]:
    col = _column(table)
    cur.execute(f"SELECT count(*) FROM {table} WHERE {col} IS NULL")
    nulls = int(cur.fetchone()[0])
    empty = 0
    if table in _EMPTY_SCOPE_TABLES:
        cur.execute(f"SELECT count(*) FROM {table} WHERE {col} = ''")
        empty = int(cur.fetchone()[0])
    return nulls, empty


def _count_orphans(cur, table: str, parent: str, key: str) -> int:
    cur.execute(f"SELECT count(*) FROM {table} c WHERE c.{key} IS NULL OR NOT EXISTS "
                f"(SELECT 1 FROM {parent} p WHERE p.id = c.{key})")
    return int(cur.fetchone()[0])


def _counted(conn, cur, unforce: list[str], count, *, lift: bool):
    """``count(cursor)`` where every row is visible: directly, or with FORCE
    lifted on ``unforce`` inside a transaction that is always rolled back.
    Returns the count, or a :data:`NOT_COUNTED` key."""
    if not unforce:
        return count(cur)
    if not lift:
        return "skipped"
    try:
        with conn.transaction(force_rollback=True):
            inner = conn.cursor()
            inner.execute(f"SET LOCAL lock_timeout = '{int(_COUNT_LOCK_TIMEOUT_MS)}ms'")
            for table in unforce:
                inner.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            return count(inner)
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "55P03":
            return "busy"
        raise


def _count_tables(conn, cur, bypass, role, tables: list[str], count, *, lift: bool):
    """Count across ``tables`` (one, or a child and its parent); return
    ``(result, method)`` where ``result`` is the count or a reason key."""
    methods = {t: _visibility(bypass, role, _catalog(cur, t)) for t in tables}
    if None in methods.values():
        return "hidden", None
    unforce = [t for t, m in methods.items() if m == "owner_no_force"]
    result = _counted(conn, cur, unforce, count, lift=lift)
    return result, ("owner_no_force" if unforce else methods[tables[0]])


def _preflight_orphans(conn, cur, bypass, role, *, lift: bool) -> dict[str, dict[str, Any]]:
    orphans: dict[str, dict[str, Any]] = {}
    for table, parent, key in _ORPHAN_CHECKS:
        if len(_existing(cur, (table, parent))) < 2:
            continue
        result, method = _count_tables(
            conn, cur, bypass, role, [table, parent],
            lambda c, t=table, p=parent, k=key: _count_orphans(c, t, p, k), lift=lift)
        counted = isinstance(result, int)
        orphans[table] = {"rows": result if counted else None, "parent": parent,
                          "counted_by": method if counted else None,
                          "not_counted": None if counted else result}
    return orphans


def preflight(conn, *, only: tuple[str, ...] | None = None, lift_force: bool = True) -> dict[str, Any]:
    """Read-only readiness report for enabling RLS.

    For each tenant-scoped table: its owner, whether the *current* role owns it
    (only the owner can ALTER / CREATE POLICY), and the count of legacy
    NULL-tenant rows and empty-tenant event rows that RLS would hide. For each
    child table (``orphans``): rows whose parent is gone or unset, which no
    workspace can see and backfill cannot assign.

    A login the policies apply to sees none of those rows, so the count is
    made where they are visible: as a superuser or BYPASSRLS login, on a table
    with no policy, or as the owner of a table whose policy is not forced. For
    a forced table the owner counts with FORCE lifted inside a transaction
    that is rolled back, waiting at most 200 ms for the table; a caller that
    must never lift it (a page view) passes ``lift_force=False``.
    ``counted_by`` names the way (:data:`COUNT_METHODS`). An uncounted table
    has ``None`` counts and a ``not_counted`` reason (:data:`NOT_COUNTED`).

    ``ready`` is True only when every table exists, is owned by the current
    role, was counted, and has no unscoped rows, and no orphaned row was
    found or left uncounted. ``only`` limits the report to a subset of
    :data:`_PREFLIGHT_TABLES` (the boot gate skips tables already protected,
    and the orphan check).
    """
    cur = conn.cursor()
    cur.execute("SELECT current_user")
    role = cur.fetchone()[0]
    cur.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
    row = cur.fetchone()
    bypass = bool(row and row[0] is True)
    tables: dict[str, dict[str, Any]] = {}
    for t in _PREFLIGHT_TABLES if only is None else only:
        # to_regclass returns NULL (no error) for a table that isn't there yet,
        # so a pre-migration DB reports cleanly instead of raising.
        if not _existing(cur, (t,)):
            tables[t] = {"owner": None, "owned_by_current_role": False,
                         "null_tenant_rows": 0, "empty_tenant_rows": 0, "missing": True,
                         "counted_by": None, "not_counted": None}
            continue
        owner = _catalog(cur, t)[0]
        result, method = _count_tables(conn, cur, bypass, role, [t],
                                       lambda c, t=t: _count_legacy(c, t), lift=lift_force)
        counted = isinstance(result, tuple)
        nulls, empty = result if counted else (None, None)
        tables[t] = {"owner": owner, "owned_by_current_role": owner == role,
                     "null_tenant_rows": nulls, "empty_tenant_rows": empty,
                     "counted_by": method if counted else None,
                     "not_counted": None if counted else result}
    orphans = {} if only is not None else _preflight_orphans(conn, cur, bypass, role,
                                                             lift=lift_force)
    ready = all(info["owned_by_current_role"] and info["null_tenant_rows"] == 0
                and not info["empty_tenant_rows"] for info in tables.values()) and all(
        info["rows"] == 0 for info in orphans.values())
    return {"role": role, "tables": tables, "orphans": orphans, "ready": ready}


def _existing(cur, tables) -> list[str]:
    found = []
    for table in tables:
        cur.execute("SELECT to_regclass(%s)", (table,))
        if cur.fetchone()[0] is not None:
            found.append(table)
    return found


__all__ = [
    "preflight",
]
