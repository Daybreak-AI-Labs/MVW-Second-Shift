"""The emergency stop reaches agents that run on other platforms."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    from maverick import killswitch, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # the stop is read through a short cache; every check in these tests is a fresh read
    check = killswitch.check
    monkeypatch.setattr(killswitch, "check", lambda **options: check(**{**options, "force_refresh": True}))
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


@pytest.fixture
def agent(app, client):
    """An enrolled outside agent's own view: a client that carries only its access key."""
    enrolled = client.post("/api/v1/external-agents", json={
        "id": "helpdesk", "platform": "copilot", "owner": "ops@example.com", "max_risk": "high"})
    assert enrolled.status_code == 201, enrolled.text
    minted = client.post("/api/v1/external-agents/helpdesk/credentials", json={"surface": "rest"})
    assert minted.status_code == 200, minted.text
    return TestClient(app, base_url="http://127.0.0.1",
                      headers={"Authorization": f"Bearer {minted.json()['token']}"})


def _stop(client):
    assert client.post("/api/v1/halt", json={"reason": "incident"}).status_code == 204


def _lift(client):
    assert client.delete("/api/v1/halt").status_code == 204


def _ask(agent, tool="lookup_user"):
    return agent.post("/api/v1/external/screen", json={"tool": tool, "risk": "low"}).json()


def test_an_agent_is_told_no_while_the_stop_is_on_and_yes_again_once_it_is_lifted(client, agent):
    assert _ask(agent)["allowed"] is True
    _stop(client)
    refused = _ask(agent)
    assert refused["allowed"] is False and refused["rule"] == "halted"
    assert "emergency stop" in refused["reason"]
    _lift(client)
    assert _ask(agent)["allowed"] is True


def test_a_risky_action_is_not_even_parked_for_approval_while_the_stop_is_on(client, agent):
    _stop(client)
    refused = agent.post("/api/v1/external/screen", json={"tool": "refund_guest", "risk": "high"}).json()
    assert refused["allowed"] is False and refused["rule"] == "halted" and "approval_id" not in refused
    assert client.get("/api/v1/approvals").json()["approvals"] == []


def test_running_work_is_told_to_stop_at_its_next_heartbeat(client, agent):
    started = agent.post("/api/v1/external/runs/start", json={"title": "Reset a password"})
    assert started.status_code == 201, started.text
    beat = f"/api/v1/external/runs/{started.json()['goal_id']}/heartbeat"
    assert agent.post(beat).json()["continue"] is True
    _stop(client)
    told = agent.post(beat).json()
    assert told["continue"] is False and "emergency stop" in told["reason"]
    _lift(client)
    assert agent.post(beat).json()["continue"] is True


def test_new_live_work_cannot_start_but_finished_work_can_still_be_reported(client, agent):
    _stop(client)
    refused = agent.post("/api/v1/external/runs/start", json={"title": "Reset a password"})
    assert refused.status_code == 403 and "emergency stop" in refused.json()["detail"]
    reported = agent.post("/api/v1/external/runs", json={"title": "Reset a password", "outcome": "success"})
    assert reported.status_code == 201, reported.text


def test_being_refused_by_the_stop_is_not_held_against_the_agent(client, agent):
    _stop(client)
    for _ in range(12):  # more than the number of refusals that blocks an agent
        assert _ask(agent)["rule"] == "halted"
    _lift(client)
    assert _ask(agent)["allowed"] is True
    (row,) = client.get("/api/v1/external-agents").json()["agents"]
    assert row["contained"] is False
    drift = client.get("/api/v1/external-agents/helpdesk/drift").json()
    assert drift["current"]["denials"] == 0 and drift["current"]["screens"] == 1  # only the one after the stop was lifted


def test_a_stop_that_cannot_be_read_refuses(client, agent, monkeypatch):
    from maverick import killswitch

    def unreadable(**options):
        raise OSError("the stop file could not be read")

    monkeypatch.setattr(killswitch, "check", unreadable)
    refused = _ask(agent)
    assert refused["allowed"] is False and refused["rule"] == "halted"


def test_concurrent_fresh_halt_checks_use_one_connection_pool(monkeypatch):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from maverick import killswitch, world_model, world_model_backends

    waiting = threading.Barrier(8, timeout=5)
    opened = []

    class World:
        def active_halt(self):
            return None

    def open_world():
        opened.append(World())
        time.sleep(0.1)
        return opened[-1]

    def check(_):
        waiting.wait()
        return killswitch._shared_halt_active(min_interval=0, fail_closed=True)

    monkeypatch.setattr(killswitch, "_shared_world", None)
    monkeypatch.setattr(world_model, "open_world", open_world)
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    with ThreadPoolExecutor(max_workers=8) as workers:
        assert list(workers.map(check, range(8))) == [None] * 8
    assert len(opened) == 1


def test_fresh_agent_halt_check_borrows_without_closing_the_dashboard_world(monkeypatch):
    from maverick import killswitch, world_model, world_model_backends

    class World:
        def active_halt(self):
            if unavailable:
                raise OSError("test store unavailable")
            return {"reason": "Operator stop", "source": "dashboard"}

        def close(self):
            pytest.fail("A borrowed world must stay open")

    unavailable = False
    handle = World()
    monkeypatch.setattr(killswitch, "_last_shared_check_ts", 0.0)
    monkeypatch.setattr(killswitch, "_last_shared_halt", None)
    monkeypatch.setattr(killswitch, "_last_shared_strict_ok", False)
    monkeypatch.setattr(world_model, "open_world", lambda: pytest.fail("Reopened the dashboard world"))
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    options = {"min_interval": 0, "fail_closed": True, "world_factory": lambda: handle}
    assert killswitch._shared_halt_active(**options) == ("Operator stop", "dashboard")
    unavailable = True
    with pytest.raises(killswitch.Halted) as failure:
        killswitch._shared_halt_active(**options)
    assert failure.value.source == "shared-error"
