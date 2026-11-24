"""Regression: WorldModel write serialisation.

The dashboard keeps a per-DB-path WorldModel singleton so requests do
not reopen SQLite and reapply migrations. ``check_same_thread=False``
alone is not thread-safe: two FastAPI threadpool workers driving execute()+commit()
on the same connection can interleave their writes so one transaction
silently includes the other's row. Worst case: thread A errors and
rolls back, thread B's "successful" insert vanishes.

The ``_writing()`` context manager + RLock make every mutating method
commit exactly one logical write. These tests prove
it under load.
"""
from __future__ import annotations

import concurrent.futures
import threading
from pathlib import Path

from maverick.world_model import WorldModel


def test_create_goal_under_thread_storm(tmp_path: Path):
    """1000 create_goal calls across 32 threads on one shared WorldModel.

    Without the lock this is flaky on macOS/Linux (one thread's row
    gets attributed to the other transaction). With the lock, every
    insert is its own committed transaction.
    """
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        N = 1000
        T = 32

        def one(i: int) -> int:
            return wm.create_goal(f"goal-{i}", f"desc-{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=T) as ex:
            ids = list(ex.map(one, range(N)))

        # Every call returned a unique lastrowid.
        assert len(set(ids)) == N

        # Every row is present in the database.
        rows = wm.list_goals()
        assert len(rows) == N

        # Titles round-trip without corruption.
        titles = {g.title for g in rows}
        assert titles == {f"goal-{i}" for i in range(N)}
    finally:
        wm.close()


def test_writing_helper_releases_lock_on_exception(tmp_path: Path):
    """An exception inside _writing() must release the lock so the next
    caller doesn't deadlock. Verifies RLock semantics + no commit().
    """
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        # Trigger an error inside the _writing() body.
        try:
            with wm._writing() as conn:
                conn.execute("INSERT INTO this_table_does_not_exist VALUES(1)")
        except Exception:
            pass

        # The lock should be free; this call must not block.
        completed = threading.Event()

        def try_write():
            wm.create_goal("after-error", "")
            completed.set()

        t = threading.Thread(target=try_write, daemon=True)
        t.start()
        t.join(timeout=2.0)
        assert completed.is_set(), "lock leaked from _writing() on exception"

        # The failed write did NOT persist (no implicit commit).
        rows = wm.list_goals()
        assert len(rows) == 1  # only the successful "after-error" goal
    finally:
        wm.close()


def test_writing_rolls_back_successful_dml_when_later_code_raises(tmp_path: Path):
    """A successful statement must not leak into a later writer's commit."""
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        try:
            with wm._writing() as conn:
                conn.execute(
                    "INSERT INTO goals(title, description, status, created_at, updated_at) "
                    "VALUES(?, ?, 'pending', ?, ?)",
                    ("stale-from-failed-write", "", 1.0, 1.0),
                )
                raise RuntimeError("boom after successful insert")
        except RuntimeError:
            pass

        wm.create_goal("next-successful-writer", "")
        titles = {g.title for g in wm.list_goals()}
        assert "next-successful-writer" in titles
        assert "stale-from-failed-write" not in titles
    finally:
        wm.close()


def test_nested_writing_does_not_commit_outer_transaction_early(tmp_path: Path):
    """Inner mutators must not commit outer writes before outer scope exits."""
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        with wm._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goals(title, description, status, created_at, updated_at) "
                "VALUES(?, ?, 'pending', ?, ?)",
                ("outer", "", 1.0, 1.0),
            )
            gid = cur.lastrowid
            wm.append_event(gid, "agent", "plan", "nested write ok")

            # While still inside outer _writing(), a separate reader must not
            # observe data yet (i.e., inner call did not commit early).
            reader = WorldModel(db)
            try:
                assert reader.conn.execute("SELECT COUNT(*) FROM goals").fetchone()[0] == 0
                assert reader.conn.execute("SELECT COUNT(*) FROM goal_events").fetchone()[0] == 0
            finally:
                reader.close()
    finally:
        wm.close()
