"""In-process wake-ups after a goal's stored state changes (timing only).

The chat page's event stream re-read the database on a timer that backed off
to two seconds while a model call ran, so a finished answer reached the page
about 1.2 s after it was saved. Writes now wake its watchers, after the commit.
"""
from __future__ import annotations

import sqlite3

import pytest

from maverick import goal_wakeup, world_model


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    path = tmp_path / "w.db"
    wm = world_model.WorldModel(path)
    return wm, path, wm.create_goal("task", "")


def _committed_events(path, goal_id):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT COUNT(*) FROM goal_events WHERE goal_id=?", (goal_id,)).fetchone()[0]


def test_a_write_nobody_watches_does_no_wake_up_work(world, monkeypatch):
    wm, path, gid = world
    monkeypatch.setattr(goal_wakeup, "_watchers", {})
    monkeypatch.setattr(goal_wakeup, "world_key", lambda _path: pytest.fail("resolved a path nobody watches"))
    monkeypatch.setattr(goal_wakeup, "notify", lambda *_a: pytest.fail("announced a change nobody watches"))
    wm.append_event(gid, "agent", "plan", "unwatched")
    wm.set_goal_status(gid, "done", "the answer")
    assert _committed_events(path, gid) == 1
