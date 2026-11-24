"""Semantic alerts survive missed polls, old task age and transaction rollback."""

import pytest
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    value = WorldModel(tmp_path / "world.db")
    yield value
    value.close()


def revision(world, goal):
    row = world.conn.execute("SELECT alert_state_revision,alert_result_revision FROM goals WHERE id=?", (goal,)).fetchone()
    return tuple(row)


def test_semantic_generation_ignores_heartbeat_and_detects_return_between_polls(world):
    goal = world.create_goal("Owned", owner="user:a")
    world.set_goal_status(goal, "blocked")
    first = revision(world, goal)
    world.set_goal_status(goal, "blocked")
    assert revision(world, goal) == first
    world.set_goal_status(goal, "active")
    world.set_goal_status(goal, "blocked")
    assert revision(world, goal)[0] == first[0] + 2
    with pytest.raises(RuntimeError), world._writing() as connection:
        connection.execute("UPDATE goals SET status='done' WHERE id=?", (goal,))
        raise RuntimeError("roll back native mutation")
    assert revision(world, goal)[0] == first[0] + 2
    assert world.get_goal(goal).status == "blocked"


def test_result_generation_only_counts_changes_after_completion(world):
    goal = world.create_goal("Owned", owner="user:a")
    world.set_goal_status(goal, "active", result="partial")
    world.set_goal_status(goal, "done", result="finished")
    assert revision(world, goal)[1] == 0
    world.set_goal_status(goal, "done", result="reviewed")
    assert revision(world, goal)[1] == 1
