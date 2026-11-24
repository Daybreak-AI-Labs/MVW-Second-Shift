"""The operator API for outside-agent drift, through the web app."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

DAY = 86400


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def _enroll(client, agent_id="helpdesk"):
    r = client.post("/api/v1/external-agents", json={"id": agent_id, "platform": "copilot", "owner": "ops@example.com"})
    assert r.status_code == 201, r.text
    return agent_id


def _normal_week(agent_id, now):
    from maverick import agent_drift

    for back in range(8, 0, -1):
        at = now - back * DAY
        for _ in range(4):
            agent_drift.observe_screen(agent_id, "lookup_policy", allowed=True, now=at)
        agent_drift.observe_run(agent_id, cost_dollars=0.2, tool_calls=4, outcome="success",
                                tools=("lookup_policy",), declared={"version": "1", "model": "m1"}, now=at)


def test_everything_answers_not_found_while_governance_is_off(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert client.get("/api/v1/agent-drift").status_code == 404
    assert client.get("/api/v1/external-agents/helpdesk/drift").status_code == 404
    assert client.post("/api/v1/external-agents/helpdesk/drift/check").status_code == 404


def test_an_agent_that_is_not_enrolled_is_not_found(client):
    assert client.get("/api/v1/external-agents/nobody/drift").status_code == 404
    r = client.post("/api/v1/external-agents/nobody/drift/acknowledge", json={"finding": "new_tool:x"})
    assert r.status_code == 404


def test_a_new_agent_has_no_baseline_and_a_thin_one_is_refused_until_forced(client):
    agent = _enroll(client)
    assert client.get(f"/api/v1/external-agents/{agent}/drift").json()["state"] == "no_baseline"
    refused = client.post(f"/api/v1/external-agents/{agent}/drift/baseline", json={})
    assert refused.status_code == 409
    assert refused.json()["detail"]  # says why, in words an operator can act on
    forced = client.post(f"/api/v1/external-agents/{agent}/drift/baseline", json={"force": True})
    assert forced.status_code == 200 and forced.json()["forced"] is True


def test_a_change_after_the_baseline_is_reported_once_and_can_be_acknowledged(client):
    from maverick import agent_drift

    agent = _enroll(client)
    now = time.time()
    _normal_week(agent, now)
    approved = client.post(f"/api/v1/external-agents/{agent}/drift/baseline", json={})
    assert approved.status_code == 200, approved.text

    for _ in range(5):
        agent_drift.observe_screen(agent, "export_records", allowed=True, now=now)
    first = client.post(f"/api/v1/external-agents/{agent}/drift/check").json()
    assert first["state"] == "drifted"
    assert "new_tool:export_records" in first["new_findings"]
    # the same finding is not reported a second time while it lasts
    assert client.post(f"/api/v1/external-agents/{agent}/drift/check").json()["new_findings"] == []

    roster = client.get("/api/v1/agent-drift").json()
    assert roster["enabled"] is True
    assert [row["state"] for row in roster["agents"] if row["agent_id"] == agent] == ["drifted"]

    page = client.get(f"/external-agents/{agent}")
    assert page.status_code == 200 and "export_records" in page.text

    ack = client.post(f"/api/v1/external-agents/{agent}/drift/acknowledge", json={"finding": "new_tool:export_records"})
    assert ack.status_code == 200
    after = client.get(f"/api/v1/external-agents/{agent}/drift").json()
    assert all(f["acknowledged"] for f in after["findings"] if f["key"] == "new_tool:export_records")


def test_request_bodies_are_strict(client):
    agent = _enroll(client)
    assert client.post(f"/api/v1/external-agents/{agent}/drift/baseline", json={"window_days": 0}).status_code == 422
    assert client.post(f"/api/v1/external-agents/{agent}/drift/baseline", json={"surprise": 1}).status_code == 422
    assert client.post(f"/api/v1/external-agents/{agent}/drift/acknowledge", json={}).status_code == 422
