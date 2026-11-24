"""Transactional template-event goal admission and durable delivery receipts.

Receipts intentionally outlive goal erasure: a historical external event may
never recreate deleted customer data or repeat its work. They contain only a
digest, a local goal ID and delivery state, not event fields or credentials.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_goal_admissions (
    admission_key TEXT PRIMARY KEY,
    trigger_key TEXT NOT NULL,
    goal_id INTEGER NOT NULL,
    delivery_state TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_pending ON event_goal_admissions(trigger_key,delivery_state);
CREATE TABLE IF NOT EXISTS event_trigger_batches (
    trigger_key TEXT PRIMARY KEY,
    batch_digest TEXT NOT NULL,
    sealed_batch TEXT NOT NULL
);
"""
POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_goal_admissions (
    tenant_id TEXT NOT NULL,
    admission_key TEXT NOT NULL,
    trigger_key TEXT NOT NULL,
    goal_id INTEGER NOT NULL,
    delivery_state TEXT NOT NULL DEFAULT 'pending',
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(tenant_id, admission_key)
);
CREATE INDEX IF NOT EXISTS idx_event_pending ON event_goal_admissions(tenant_id,trigger_key,delivery_state);
CREATE TABLE IF NOT EXISTS event_trigger_batches (
    tenant_id TEXT NOT NULL,
    trigger_key TEXT NOT NULL,
    batch_digest TEXT NOT NULL,
    sealed_batch TEXT NOT NULL,
    PRIMARY KEY(tenant_id,trigger_key)
);
"""


class LegacyEventGoalHeld(RuntimeError):
    """An unstarted event goal predates the verified admission protocol."""


class EventRegistryUnavailable(RuntimeError):
    """The automation registry cannot be read; execution may be retried later."""


def compatible_legacy_goal(origin: str, owner: str, trigger_key: str) -> bool:
    """Prove an old non-mail goal still belongs to its unchanged binding.

    The old receipt retained the trigger generation even though its origin did
    not. A missing receipt, registry, or immutable template is never proof.
    """
    return _compatible_goal_binding(origin, owner, trigger_key, allow_mail=False)


def compatible_current_goal(origin: str, owner: str, trigger_key: str) -> bool:
    """Prove a queued v2 goal still has its exact approved event binding.

    The poller verifies email senders before admitting a v2 goal. A later
    trigger edit (including its permitted senders) changes the generation and
    must revoke an unstarted goal before either local or remote execution.
    """
    return _compatible_goal_binding(origin, owner, trigger_key, allow_mail=True)


def compatible_event_goal(kind: str, origin: str, owner: str,
                          trigger_key: str) -> bool:
    if kind == "event":
        return compatible_legacy_goal(origin, owner, trigger_key)
    if kind == "event_v2":
        return compatible_current_goal(origin, owner, trigger_key)
    return False


@contextmanager
def execution_binding_lock(world, goal_id: int):
    """Pin an event binding through the pending-to-active transaction.

    Trigger edits take the dashboard registry lock. The read here finishes
    before acquiring that lock, then callers enter the world write transaction;
    this order also matches public-form decisions (registry before world).
    Callers must retry, rather than start, if an event origin appears between
    this preflight and their transactional origin read.
    """
    from .world_model import WorldModel

    if isinstance(world, WorldModel):
        event = world._read_one(
            "SELECT 1 FROM goal_origins WHERE goal_id=? "
            "AND kind IN ('event','event_v2')", (int(goal_id),),
        ) is not None
        if event:
            from threading import get_ident

            if world._writer_ident == get_ident():
                raise EventRegistryUnavailable(
                    "Event execution must begin outside a world transaction"
                )
    else:
        from .world_model_backends.postgres import PostgresWorldModel, _mutation_tenant_scope

        if not isinstance(world, PostgresWorldModel):
            raise TypeError("event execution requires a supported world model")
        if getattr(getattr(world, "_tx_depth", None), "value", 0):
            # A nested transaction already holds a world connection/row lock.
            # Acquiring the file registry now would invert the form/trigger
            # lock order, and the inner commit may precede the outer commit.
            raise EventRegistryUnavailable(
                "Event execution must begin outside a world transaction"
            )
        scoped, params = _mutation_tenant_scope("g.tenant_id")
        with world._tx() as cursor:
            cursor.execute(
                "SELECT 1 FROM goal_origins o JOIN goals g ON g.id=o.goal_id "
                "WHERE o.goal_id=%s AND o.kind IN ('event','event_v2') "
                "AND " + scoped,
                (int(goal_id), *params),
            )
            event = cursor.fetchone() is not None

    if event:
        try:
            from maverick_dashboard import event_triggers_store

            lock = event_triggers_store.registry_lock()
            lock.__enter__()
        except (ImportError, OSError, RuntimeError) as exc:
            raise EventRegistryUnavailable("Event automation registry lock is unavailable") from exc
        try:
            yield True
        finally:
            lock.__exit__(None, None, None)
    else:
        yield False


def _compatible_goal_binding(origin: str, owner: str, trigger_key: str, *,
                             allow_mail: bool) -> bool:
    if not origin or not trigger_key:
        return False
    try:
        from maverick_dashboard import event_triggers_store, triggers_store
        from maverick_dashboard.event_poll import _trigger_key

        from maverick.paths import current_tenant_id

        current = event_triggers_store.get_trigger(
            origin, tenant=current_tenant_id() or "", strict=True,
        )
        if (current is None or not current.get("source")
                or (current["source"] == "imap_email" and not allow_mail)
                or current.get("owner") != owner
                or current.get("flow")
                or _trigger_key(current) != trigger_key):
            return False
        triggers_store.bound_template(current)
        return True
    except EventRegistryUnavailable:
        raise
    except Exception:
        # A damaged/unreadable registry cannot authorize an old reservation.
        return False


@contextmanager
def _transaction(world, admission_key):
    from .paths import current_tenant_id_strict
    from .world_model import WorldModel
    from .world_model_backends.postgres import PostgresWorldModel, _active_tenant

    context_tenant = current_tenant_id_strict()
    if isinstance(world, WorldModel):
        if world._event_admission_tenant != context_tenant:
            raise ValueError("event world belongs to a different tenant context")
        with world._writing() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            yield conn, "?", "admission_key=?", (admission_key,), False
            if current_tenant_id_strict() != context_tenant:
                raise ValueError("event admission tenant context changed")
    elif isinstance(world, PostgresWorldModel):
        tenant = _active_tenant() or ""
        lock = int.from_bytes(hashlib.sha256(
            f"{tenant}:{admission_key}".encode()).digest()[:8], "big", signed=True)
        with world._tx() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
            yield cur, "%s", "tenant_id=%s AND admission_key=%s", (tenant, admission_key), True
            if current_tenant_id_strict() != context_tenant:
                raise ValueError("event admission tenant context changed")
    else:
        raise TypeError("template event admission requires a transactional world model")
