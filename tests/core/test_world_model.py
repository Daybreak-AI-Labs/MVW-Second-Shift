"""Tests for the world model (maverick.world_model): file permissions, processed
messages, orphan reclaim and connection lifecycle.
"""
from __future__ import annotations

import os
import stat

import pytest


def test_world_db_permissions_locked(tmp_path):
    from maverick.world_model import WorldModel
    p = tmp_path / "w.db"
    wm = WorldModel(p)
    wm.close()
    mode = stat.S_IMODE(os.stat(p).st_mode)
    if os.name != "nt":  # POSIX mode bits aren't meaningful on NTFS
        assert mode & 0o077 == 0  # no group/other access


class TestWorldDBPerms:
    @pytest.mark.skipif(os.name != "posix", reason="POSIX perms")
    def test_db_file_created_0600(self, tmp_path):
        from maverick.world_model import open_world
        db = tmp_path / "world.db"
        w = open_world(db)
        try:
            mode = stat.S_IMODE(db.stat().st_mode)
            assert mode == 0o600, oct(mode)
        finally:
            w.close()


def test_foreign_keys_on(tmp_path):
    """PRAGMA foreign_keys=ON so REFERENCES clauses actually do something."""
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "w.db")
    row = wm.conn.execute("PRAGMA foreign_keys").fetchone()
    assert row[0] == 1


def test_schema_version_init_handles_concurrent_inserts(tmp_path, monkeypatch):
    """Two WorldModel constructions on the same fresh DB don't crash
    on the schema_version PRIMARY KEY collision."""
    from maverick.world_model import WorldModel

    db = tmp_path / "race.db"
    # First connection initializes.
    wm1 = WorldModel(db)
    # Second connection on the same DB must not raise IntegrityError
    # under the now-correct INSERT-OR-IGNORE check-then-insert path.
    wm2 = WorldModel(db)
    assert wm1.schema_version == wm2.schema_version


class TestWorldModelClose:
    def test_close_closes_connection(self, tmp_path):
        from maverick.world_model import WorldModel
        wm = WorldModel(tmp_path / "w.db")
        wm.close()
        # After close, queries raise sqlite3.ProgrammingError.
        import sqlite3
        with pytest.raises(sqlite3.ProgrammingError):
            wm.conn.execute("SELECT 1")

    def test_context_manager_closes(self, tmp_path):
        from maverick.world_model import WorldModel
        with WorldModel(tmp_path / "w.db") as wm:
            wm.create_goal("x", "")
        import sqlite3
        with pytest.raises(sqlite3.ProgrammingError):
            wm.conn.execute("SELECT 1")


def test_an_interrupted_write_is_rolled_back_not_left_for_the_next_write(tmp_path):
    from maverick.world_model import WorldModel

    wm = WorldModel(tmp_path / "w.db")
    try:
        with pytest.raises(KeyboardInterrupt):
            with wm._writing() as conn:
                conn.execute("INSERT INTO episodes(goal_id, started_at) VALUES (NULL, 1.0)")
                raise KeyboardInterrupt
        assert not wm.conn.in_transaction
        assert wm.conn.execute("SELECT COUNT(*) FROM episodes").fetchone()[0] == 0
    finally:
        wm.close()
