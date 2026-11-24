"""WorldModel shares one sqlite connection across threads (serve runs many
goal threads). Reads must serialise against the _writing() critical section
on the same RLock, or a read can observe a writer's uncommitted (and
possibly rolled-back) transaction on that connection.
"""
from __future__ import annotations


def test_read_within_write_does_not_deadlock(tmp_path):
    """A read issued while this thread holds the write lock must return
    (RLock is reentrant), not self-deadlock."""
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("g")
    with w._writing() as conn:
        conn.execute("UPDATE goals SET title = 'x' WHERE id = ?", (gid,))
        got = w.get_goal(gid)          # read nested inside the open write txn
    assert got is not None
    w.close()
