"""PostgresWorldModel round-trip — runs only when MAVERICK_PG_DSN is set.

Skipped locally and in the normal test matrix (no Postgres available); the
dedicated CI ``postgres`` job stands up a Postgres service + DSN and runs this.
It's the first DB-backed test for the Postgres backend and the harness future
method-parity work can extend (so parity is testable, not shipped blind).
"""
from __future__ import annotations
import os
import uuid
from types import SimpleNamespace

import pytest

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = [pytest.mark.usefixtures("postgres_test_dsn"), pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)]


@pytest.fixture
def world():
    from maverick.world_model_backends.postgres import PostgresWorldModel
    w = PostgresWorldModel(dsn=_DSN)
    try:
        yield w
    finally:
        w.close()


def test_connection_timeouts_and_operator_options_survive_real_reconnect(monkeypatch):
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg.conninfo import make_conninfo

    monkeypatch.setenv("MAVERICK_PG_IDLE_TX_TIMEOUT_MS", "60000")
    dsn = make_conninfo(_DSN, options="-c statement_timeout=12345 -c application_name=lightwork-test")
    with PostgresWorldModel(dsn) as database:
        for reconnect in (False, True):
            if reconnect:
                database.conn.close()
            with database._tx() as cursor:
                cursor.execute("SELECT current_setting('statement_timeout'), "
                               "current_setting('idle_in_transaction_session_timeout'), "
                               "current_setting('application_name')")
                assert cursor.fetchone() == ("12345ms", "1min", "lightwork-test")


def test_status_only_update_preserves_result(world):
    # COALESCE(%s, result): a later status-only update (result=None) must not
    # wipe an existing result.
    gid = world.create_goal("g")
    world.set_goal_status(gid, "running", result="partial")
    world.set_goal_status(gid, "done")
    assert world.get_goal(gid).result == "partial"


def test_goal_execution_claim_is_atomic(world):
    gid = world.create_goal("claim exactly once")

    assert world.claim_goal_for_run(gid) is True
    assert world.get_goal(gid).status == "active"
    assert world.claim_goal_for_run(gid) is False


def test_goal_execution_claim_honors_expected_owner(world):
    gid = world.create_goal("owner-scoped claim", owner="agent:alice")

    assert world.claim_goal_for_run(gid, expected_owner="agent:bob") is False
    assert world.get_goal(gid).status == "pending"
    assert world.claim_goal_for_run(gid, expected_owner="agent:alice") is True
    assert world.get_goal(gid).status == "active"


def test_get_missing_goal_returns_none(world):
    assert world.get_goal(999_999_999) is None


def test_episode_round_trip(world):
    # No episode-read method on the PG backend yet; the assertion is that the
    # insert + update commit without raising (and return a real id).
    gid = world.create_goal("episodic")
    eid = world.start_episode(gid)
    assert isinstance(eid, int)
    world.end_episode(
        eid, "did the thing", "success",
        cost_dollars=0.02, input_tokens=10, output_tokens=5, tool_calls=2,
    )


def test_list_goals_filter_and_order(world):
    g1 = world.create_goal("first")
    g2 = world.create_goal("second")
    world.set_goal_status(g2, "done")

    done = world.list_goals(status="done")
    assert any(x.id == g2 for x in done)
    assert all(x.status == "done" for x in done)  # filter applied

    desc = world.list_goals(order="desc", limit=100)
    ids = [x.id for x in desc]
    assert ids.index(g2) < ids.index(g1)  # later id first in DESC order


def test_list_episodes_and_total_spend(world):
    gid = world.create_goal("spendy")
    eid = world.start_episode(gid)
    world.end_episode(
        eid, "s", "success",
        cost_dollars=1.5, input_tokens=100, output_tokens=50, tool_calls=3,
    )
    eps = world.list_episodes(goal_id=gid)
    assert any(x.id == eid and x.cost_dollars == 1.5 for x in eps)

    totals = world.total_spend()
    assert totals["dollars"] >= 1.5   # this run's ended episode counts
    assert totals["runs"] >= 1


def test_total_spend_accepts_owner_kwarg(world):
    """total_spend(owner=...) used to
    raise TypeError on this backend -- it took no owner argument at all,
    while the SQLite backend (and /api/v1/spend, external-agent spend
    records) call it with one."""
    token = uuid.uuid4().hex
    alice = f"user:spend-alice:{token}"
    bob = f"user:spend-bob:{token}"

    alice_gid = world.create_goal("alice spend", owner=alice)
    world.end_episode(world.start_episode(alice_gid), "done", "success",
                      cost_dollars=2.0, input_tokens=10, output_tokens=5)
    bob_gid = world.create_goal("bob spend", owner=bob)
    world.end_episode(world.start_episode(bob_gid), "done", "success",
                      cost_dollars=9.0, input_tokens=20, output_tokens=8)

    alice_totals = world.total_spend(owner=alice)
    assert alice_totals["dollars"] == 2.0
    assert alice_totals["runs"] == 1

    bob_totals = world.total_spend(owner=bob)
    assert bob_totals["dollars"] == 9.0

    # None is still the deployment-wide admin view (unfiltered by owner).
    admin_totals = world.total_spend()
    assert admin_totals["dollars"] >= 11.0


def test_list_episodes_owner_scope_matches_sqlite(world):
    import uuid

    token = uuid.uuid4().hex
    alice = f"user:alice:{token}"
    bob = f"user:bob:{token}"

    alice_gid = world.create_goal("alice-owned run", owner=alice)
    alice_eid = world.start_episode(alice_gid)
    world.end_episode(alice_eid, "done", "success", cost_dollars=1.25)

    bob_gid = world.create_goal("bob-owned run", owner=bob)
    bob_eid = world.start_episode(bob_gid)
    world.end_episode(bob_eid, "done", "success", cost_dollars=7.5)

    legacy_gid = world.create_goal("legacy owner default")
    legacy_eid = world.start_episode(legacy_gid)
    world.end_episode(legacy_eid, "done", "success", cost_dollars=0.5)

    assert [e.id for e in world.list_episodes(owner=alice)] == [alice_eid]
    assert [e.id for e in world.list_episodes(owner=bob)] == [bob_eid]
    assert world.list_episodes(owner=f"user:nobody:{token}") == []

    # Owner and goal scopes are cumulative: Alice cannot select Bob's run by id.
    assert world.list_episodes(goal_id=bob_gid, owner=alice) == []

    # None retains the admin/auth-off view; the empty owner retains legacy rows.
    admin_ids = {e.id for e in world.list_episodes(limit=10_000)}
    assert {alice_eid, bob_eid, legacy_eid} <= admin_ids
    legacy_ids = {e.id for e in world.list_episodes(limit=10_000, owner="")}
    assert legacy_eid in legacy_ids

    # The create path stores ownership and the migration default, not only the
    # read query's shape.
    with world._tx() as cur:
        cur.execute(
            "SELECT id, owner FROM goals WHERE id IN (%s, %s, %s)",
            (alice_gid, bob_gid, legacy_gid),
        )
        owners = dict(cur.fetchall())
    assert owners == {alice_gid: alice, bob_gid: bob, legacy_gid: ""}


def test_goal_reads_are_owner_scoped(world):
    import uuid

    token = uuid.uuid4().hex
    alpha = f"agent:alpha:{token}"
    bravo = f"agent:bravo:{token}"
    alpha_gid = world.create_goal("alpha private", owner=alpha)
    bravo_gid = world.create_goal("bravo private", owner=bravo)

    assert world.get_goal(alpha_gid).owner == alpha
    assert {g.id for g in world.list_goals(owner=alpha)} == {alpha_gid}
    assert {g.id for g in world.list_goals(owner=bravo)} == {bravo_gid}
    assert world.list_goals(owner=f"agent:nobody:{token}") == []


def test_schema_version_is_int(world):
    assert isinstance(world.schema_version, int)
    assert world.schema_version >= 1


def test_pooled_backend_crud_and_pool_object(monkeypatch):
    """With [world_model] pool_size > 0 the backend uses a psycopg_pool pool;
    CRUD still works and self._pool is wired (self.conn is None)."""
    pytest.importorskip("psycopg_pool")
    monkeypatch.setenv("MAVERICK_PG_POOL_SIZE", "3")
    from maverick.world_model_backends.postgres import PostgresWorldModel
    w = PostgresWorldModel(dsn=_DSN)
    try:
        assert w._pool is not None and w.conn is None
        gid = w.create_goal("pooled-goal", description="via pool")
        got = w.get_goal(gid)
        assert got is not None and got.title == "pooled-goal"
        w.set_goal_status(gid, "done", result="ok")
        assert w.get_goal(gid).status == "done"
    finally:
        w.close()


def _disable_rls(dsn):
    """Tear down RLS so the opt-in test doesn't leak FORCE RLS into other
    tests sharing the database."""
    import psycopg
    from maverick.world_model_backends.postgres import _TENANT_TABLES
    with psycopg.connect(dsn, autocommit=True) as c, c.cursor() as cur:
        for t in _TENANT_TABLES:
            cur.execute(f"DROP POLICY IF EXISTS mvk_tenant_isolation ON {t}")
            cur.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
            cur.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")


def test_rls_enforces_tenant_isolation_at_db_level(monkeypatch):
    """With RLS on, a tenant-scoped transaction sees ONLY its own rows even on
    a RAW query that carries no app-layer predicate — i.e. the database, not
    just _tenant_scope, enforces the boundary. No active tenant sees no rows
    through the fail-closed policy.

    RLS is bypassed for superusers and table owners-without-FORCE, so this must
    connect as a dedicated NON-superuser role to actually exercise the policy
    (the CI/test DSN role is a superuser). The owner applies the policy; the
    app role only enforces it."""
    import psycopg
    from maverick.paths import reset_tenant, set_tenant
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg.conninfo import make_conninfo

    monkeypatch.setenv("MAVERICK_PG_RLS", "1")
    # Install/apply the owner schema before granting rights on existing tables.
    # Each test now starts from its own empty database.
    PostgresWorldModel(dsn=_DSN).close()
    # 1. Create a non-superuser app role with DML rights (as the owner/superuser).
    with psycopg.connect(_DSN, autocommit=True) as c, c.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mvk_rls_app")
        cur.execute("CREATE ROLE mvk_rls_app LOGIN PASSWORD 'rlspw' NOSUPERUSER NOBYPASSRLS")  # pragma: allowlist secret
        cur.execute("GRANT USAGE, CREATE ON SCHEMA public TO mvk_rls_app")
        cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO mvk_rls_app")
        cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO mvk_rls_app")

    app_dsn = make_conninfo(_DSN, user="mvk_rls_app", password="rlspw")  # pragma: allowlist secret
    # 2. Owner applies RLS; 3. app role (non-superuser) enforces it.
    PostgresWorldModel(dsn=_DSN).close()
    w = PostgresWorldModel(dsn=app_dsn)
    try:
        tok = set_tenant("rls_alpha")
        try:
            a = w.create_goal("alpha-secret")
        finally:
            reset_tenant(tok)
        tok = set_tenant("rls_beta")
        try:
            b = w.create_goal("beta-secret")
        finally:
            reset_tenant(tok)

        # RAW count (no _tenant_scope) under alpha -> RLS must hide beta's row.
        tok = set_tenant("rls_alpha")
        try:
            with w._tx() as cur:
                cur.execute("SELECT count(*) FROM goals WHERE id IN (%s, %s)", (a, b))
                visible = int(cur.fetchone()[0])
        finally:
            reset_tenant(tok)
        assert visible == 1, "RLS should expose only the active tenant's row"

        # No active tenant gets an impossible GUC sentinel, so RLS fails closed.
        with w._tx() as cur:
            cur.execute("SELECT count(*) FROM goals WHERE id IN (%s, %s)", (a, b))
            assert int(cur.fetchone()[0]) == 0
    finally:
        w.close()
        _disable_rls(_DSN)
        with psycopg.connect(_DSN, autocommit=True) as c, c.cursor() as cur:
            cur.execute("REASSIGN OWNED BY mvk_rls_app TO CURRENT_USER")
            cur.execute("DROP OWNED BY mvk_rls_app")
            cur.execute("DROP ROLE IF EXISTS mvk_rls_app")


def test_halt_durable_clear_failure_rolls_back_locked_generation(world):
    prior = world.active_halt()
    if prior is not None:
        world.disarm_halt(expected_generation=prior["generation"])

    try:
        world.arm_halt("incident", source="postgres-test")
        observed = world.active_halt()
        callbacks = []

        def _local_clear_failure():
            callbacks.append("attempted")
            raise OSError("local clear failed")

        with pytest.raises(OSError, match="local clear failed"):
            world.disarm_halt(
                expected_generation=observed["generation"],
                durable_clear=_local_clear_failure,
            )

        assert callbacks == ["attempted"]
        assert world.active_halt() == observed
    finally:
        current = world.active_halt()
        if current is not None:
            world.disarm_halt(expected_generation=current["generation"])


def test_list_approvals_newest_first(world, monkeypatch):
    from maverick.world_model_backends import postgres

    # Equal timestamps need a deterministic tie-breaker, including on clocks
    # with coarse resolution. Do not sleep to make an unstable query pass.
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: 1_000.0))
    a1 = world.create_approval("act-one", risk="high")
    a2 = world.create_approval("act-two", risk="low")
    ids = [a.id for a in world.list_approvals()]
    assert a1 in ids and a2 in ids
    assert ids.index(a2) < ids.index(a1)  # newest (a2) first
    assert [row.id for row in world.list_approvals(limit=1)] == [a2]


def test_concurrent_migrate_does_not_race(world):
    # Advisory lock (audit follow-up): many replicas migrating the same DB at
    # once must not error -- Postgres CREATE/ALTER ... IF NOT EXISTS DDL is not
    # concurrency-safe without serialization. Each thread opens its own backend
    # (its own connection) and runs migration on construction.
    import threading

    from maverick.world_model_backends.postgres import (
        _PG_SCHEMA_VERSION,
        PostgresWorldModel,
    )

    errs: list[str] = []

    def go():
        try:
            w = PostgresWorldModel(dsn=_DSN)
            w.close()
        except Exception as e:  # noqa: BLE001
            errs.append(repr(e))

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errs == [], f"concurrent migration raced: {errs}"
    assert world.schema_version == _PG_SCHEMA_VERSION


@pytest.mark.parametrize("pool_size", ["0", "1"])
def test_nested_tx_joins_the_outer_transaction(monkeypatch, pool_size):
    """A read inside an open transaction (a submission guard reading the world)
    used to commit the outer transaction so far, or wait on a second pooled
    connection. It now runs inside the outer transaction."""
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_PG_POOL_SIZE", pool_size)
    w = PostgresWorldModel(dsn=_DSN)
    title = f"nested-tx-{pool_size}-{os.getpid()}"
    try:
        with pytest.raises(RuntimeError, match="outer fails"):
            with w._tx() as cur:
                cur.execute("INSERT INTO goals (title, status, created_at, updated_at) "
                            "VALUES (%s, 'pending', 0, 0)", (title,))
                seen = w.query("SELECT COUNT(*) FROM goals WHERE title=?", (title,))
                assert seen[0][0] == 1  # the inner read sees the outer write
                import psycopg

                with pytest.raises(psycopg.errors.UndefinedColumn):
                    w.query("SELECT no_such_column FROM goals")
                cur.execute("SELECT 1")  # an inner failure leaves the outer usable
                raise RuntimeError("outer fails")
        assert w.query("SELECT COUNT(*) FROM goals WHERE title=?", (title,))[0][0] == 0
    finally:
        w.close()
