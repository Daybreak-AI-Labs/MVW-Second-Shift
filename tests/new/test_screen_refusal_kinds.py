"""Two additions to what an outside agent is told and can say, both backward compatible:

* a refusal from ``/api/v1/external/screen`` carries a ``kind`` so an agent can tell "no" from "try later";
* ``/api/v1/external/runs/start`` accepts the same optional ``declared`` build as a run report, so drift knows
  the agent's build before its first action.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

KINDS = {"denied", "approval_required", "halted", "contained", "limit", "unavailable"}


@pytest.fixture
def app(tmp_path, monkeypatch):
    from maverick import killswitch, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    check = killswitch.check
    monkeypatch.setattr(killswitch, "check", lambda **options: check(**{**options, "force_refresh": True}))
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def _agent(app, client, **enroll):
    body = {"id": "helpdesk", "platform": "copilot", "owner": "ops@example.com", "max_risk": "high",
            "allow_tools": ["lookup_user:low", "refund_guest:high"], **enroll}
    assert client.post("/api/v1/external-agents", json=body).status_code == 201
    minted = client.post("/api/v1/external-agents/helpdesk/credentials", json={"surface": "rest"})
    assert minted.status_code == 200, minted.text
    return TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {minted.json()['token']}"})


def _screen(agent, tool="lookup_user", risk="low"):
    return agent.post("/api/v1/external/screen", json={"tool": tool, "risk": risk}).json()


def test_an_allowed_answer_has_no_kind(app, client):
    answer = _screen(_agent(app, client))
    assert answer["allowed"] is True and "kind" not in answer


def test_a_tool_outside_the_agents_list_is_denied(app, client):
    answer = _screen(_agent(app, client), tool="wire_transfer")
    assert answer["allowed"] is False and answer["kind"] == "denied"


def test_a_risk_above_the_ceiling_is_denied(app, client):
    answer = _screen(_agent(app, client, max_risk="low"), tool="refund_guest", risk="high")
    assert answer["allowed"] is False and answer["kind"] == "denied"


def test_an_action_that_needs_a_person_says_so_and_keeps_its_approval_fields(app, client):
    answer = _screen(_agent(app, client), tool="refund_guest", risk="high")
    assert answer["allowed"] is False and answer["kind"] == "approval_required"
    assert answer["requires_approval"] is True and isinstance(answer["approval_id"], int)
    assert len(answer["approval_binding_sha256"]) == 64
    assert answer["rule"] == "approval_required"  # the older field is unchanged


def test_the_emergency_stop_is_halted(app, client):
    agent = _agent(app, client)
    assert client.post("/api/v1/halt", json={"reason": "incident"}).status_code == 204
    answer = _screen(agent)
    assert answer["allowed"] is False and answer["kind"] == "halted" and answer["rule"] == "halted"
    assert client.delete("/api/v1/halt").status_code == 204
    assert _screen(agent)["allowed"] is True


def test_a_contained_agent_is_told_so(app, client):
    from maverick import external_agents

    agent = _agent(app, client)
    assert external_agents.contain("helpdesk", contained_by="soc")
    answer = _screen(agent)
    assert answer["allowed"] is False and answer["kind"] == "contained"


def test_a_spent_budget_is_a_limit(app, client, monkeypatch):
    from maverick import external_agents

    agent = _agent(app, client, max_dollars=1.0)
    monkeypatch.setattr(external_agents, "_period_spent", lambda meta, now=None: 5.0)
    answer = _screen(agent)
    assert answer["allowed"] is False and answer["rule"] == "budget" and answer["kind"] == "limit"


def test_a_screen_that_could_not_be_decided_is_unavailable(app, client, monkeypatch):
    agent = _agent(app, client)

    class Broken:
        def scan_input(self, text):
            raise RuntimeError("scanner down")

    from maverick_dashboard import external_gateway

    monkeypatch.setattr(external_gateway, "_shield", lambda: Broken())
    answer = agent.post("/api/v1/external/screen", json={"tool": "lookup_user", "risk": "low", "detail": "x"}).json()
    assert answer["allowed"] is False and answer["rule"] == "screen_error" and answer["kind"] == "unavailable"


@pytest.mark.parametrize("rule,kind", [
    ("approval_required", "approval_required"), ("halted", "halted"), ("contained", "contained"),
    ("budget", "limit"), ("approval_backlog", "limit"), ("execution_backlog", "limit"),
    ("disabled", "unavailable"), ("screen_error", "unavailable"), ("approval_unavailable", "unavailable"),
    ("not_enrolled", "unavailable"),
    ("shield", "denied"), ("bad_risk", "denied"), ("not_in_registry", "denied"), ("anything_else", "denied"),
])
def test_every_rule_maps_to_one_known_kind(rule, kind):
    from maverick import external_agents

    assert external_agents.refusal_kind(rule) == kind and kind in KINDS


def test_the_connection_file_lists_the_kinds(app):
    spec = TestClient(app, base_url="http://127.0.0.1").get("/api/v1/external/openapi.json").json()
    reply = spec["paths"]["/api/v1/external/screen"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert set(reply["properties"]["kind"]["enum"]) == KINDS


# --- declared on start ---------------------------------------------------------------------------------

def _drift(client):
    return client.get("/api/v1/external-agents/helpdesk/drift").json()


def test_a_run_started_with_its_build_tells_drift_before_any_action(app, client):
    agent = _agent(app, client)
    started = agent.post("/api/v1/external/runs/start", json={
        "title": "Reset a password", "declared": {"version": "3", "model": "gpt-x", "config_digest": "d" * 64}})
    assert started.status_code == 201, started.text
    declared = _drift(client)["config"]["declared"]
    assert (declared["version"], declared["model"]) == ("3", "gpt-x")
    assert declared["config_digest"]


def test_starting_without_a_build_still_works_and_records_none(app, client):
    agent = _agent(app, client)
    assert agent.post("/api/v1/external/runs/start", json={"title": "Reset a password"}).status_code == 201
    assert _drift(client)["config"]["declared"] == {}


@pytest.mark.parametrize("declared", [{"version": "v" * 201}, "3", ["3"]])
def test_a_malformed_build_on_start_is_refused_and_no_run_is_opened(app, client, declared):
    agent = _agent(app, client)
    sent = agent.post("/api/v1/external/runs/start", json={"title": "Reset a password", "declared": declared})
    assert sent.status_code == 422
    assert client.get("/api/v1/approvals").status_code == 200


def test_the_connection_file_publishes_declared_on_start(app):
    spec = TestClient(app, base_url="http://127.0.0.1").get("/api/v1/external/openapi.json").json()
    properties = spec["paths"]["/api/v1/external/runs/start"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]
    assert set(properties["declared"]["properties"]) == {"version", "config_digest", "model"}
