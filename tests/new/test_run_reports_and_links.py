"""What an outside agent can tell Second Shift about a run, the connection
file it is given, and the link from an enrolled agent to its platform record."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


@pytest.fixture
def agent(app, client):
    """An enrolled agent's own view: a client that carries only its access key."""
    _enroll(client)
    minted = client.post("/api/v1/external-agents/helpdesk/credentials", json={"surface": "rest"})
    assert minted.status_code == 200, minted.text
    return TestClient(app, base_url="http://127.0.0.1",
                      headers={"Authorization": f"Bearer {minted.json()['token']}"})


def _enroll(client, agent_id="helpdesk", **fields):
    body = {"id": agent_id, "platform": "copilot", "owner": "ops@example.com", **fields}
    return client.post("/api/v1/external-agents", json=body)


def _drift(client, agent_id="helpdesk"):
    return client.get(f"/api/v1/external-agents/{agent_id}/drift").json()


# --- run reports -------------------------------------------------------------

def test_a_run_report_carries_tool_names_and_the_declared_build_to_drift(client, agent):
    sent = agent.post("/api/v1/external/runs", json={
        "title": "Reset a password", "outcome": "success",
        "tools": ["lookup_user", "lookup_user", "reset_password"],
        "declared": {"version": "1.4", "model": "model-a", "config_digest": "c" * 150}})
    assert sent.status_code == 201, sent.text
    seen = _drift(client)
    assert seen["current"]["tools"] == {"lookup_user": 2, "reset_password": 1}
    declared = seen["config"]["declared"]
    assert (declared["version"], declared["model"]) == ("1.4", "model-a")
    # a long value is kept as a digest, never as the text the agent sent
    assert declared["config_digest"].startswith("sha256:") and "c" * 20 not in declared["config_digest"]


def test_closing_a_live_run_carries_the_same_two_fields(client, agent):
    started = agent.post("/api/v1/external/runs/start", json={"title": "Reset a password"})
    assert started.status_code == 201, started.text
    closed = agent.post(f"/api/v1/external/runs/{started.json()['goal_id']}/finish", json={
        "outcome": "success", "tools": ["reset_password"], "declared": {"version": "2.0"}})
    assert closed.status_code == 200, closed.text
    seen = _drift(client)
    assert seen["current"]["tools"] == {"reset_password": 1}
    assert seen["config"]["declared"]["version"] == "2.0"


def test_live_agent_storage_runs_off_the_event_loop_with_the_dashboard_world(agent, monkeypatch):
    import asyncio
    from functools import wraps

    from maverick import external_agents
    from maverick_dashboard import _shared

    world = _shared._world()
    calls = []

    def observe(name, operation):
        @wraps(operation)
        def observed(*args, **kwargs):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                off_loop = True
            else:
                off_loop = False
            factory = kwargs.get("world_factory")
            calls.append((name, off_loop, factory is not None and factory() is world))
            return operation(*args, **kwargs)

        return observed

    for name in ("start_run", "heartbeat", "finish_run", "approval_status"):
        monkeypatch.setattr(external_agents, name, observe(name, getattr(external_agents, name)))

    started = agent.post("/api/v1/external/runs/start", json={"title": "Reset a password"})
    assert started.status_code == 201, started.text
    path = f"/api/v1/external/runs/{started.json()['goal_id']}"
    assert agent.post(f"{path}/heartbeat").json()["continue"] is True
    assert agent.post(f"{path}/finish", json={"outcome": "success"}).status_code == 200
    assert agent.get("/api/v1/external/approvals/999").status_code == 404
    assert calls == [(name, True, True) for name in ("start_run", "heartbeat", "finish_run", "approval_status")]


def test_agent_only_routes_do_not_dispatch_browser_identity_or_visibility(agent, monkeypatch):
    from maverick_dashboard import app, auth

    def browser_only(*args, **kwargs):
        pytest.fail("The gateway already verified its own credential")

    monkeypatch.setattr(auth, "_verify_off_loop", browser_only)
    monkeypatch.setattr(app, "enforce_page_visibility", browser_only)
    assert agent.post("/api/v1/external/screen", json={"tool": "lookup_user", "risk": "low"}).json()["allowed"]


def test_a_report_without_the_new_fields_is_still_accepted(client, agent):
    sent = agent.post("/api/v1/external/runs", json={"title": "Reset a password", "outcome": "success"})
    assert sent.status_code == 201, sent.text
    seen = _drift(client)
    assert seen["current"]["runs"] == 1 and seen["current"]["tools"] == {}
    assert seen["config"]["declared"] == {}


@pytest.mark.parametrize("fields", [
    {"tools": ["t"] * 1001},
    {"tools": ["t" * 257]},
    {"tools": "reset_password"},
    {"tools": [{"name": "reset_password"}]},
    {"declared": {"version": "v" * 201}},
    {"declared": "1.4"},
])
def test_a_malformed_tool_list_or_declaration_is_refused_and_nothing_is_recorded(client, agent, fields):
    sent = agent.post("/api/v1/external/runs", json={"title": "Reset a password", "outcome": "success", **fields})
    assert sent.status_code == 422
    assert _drift(client)["current"]["runs"] == 0


def test_a_changed_declared_model_is_reported_after_the_baseline_is_approved(client, agent):
    for _ in range(6):
        agent.post("/api/v1/external/runs", json={"title": "Reset a password", "outcome": "success",
                                                  "tools": ["reset_password"], "declared": {"model": "model-a"}})
    approved = client.post("/api/v1/external-agents/helpdesk/drift/baseline", json={"force": True})
    assert approved.status_code == 200, approved.text
    agent.post("/api/v1/external/runs", json={"title": "Reset a password", "outcome": "success",
                                              "tools": ["reset_password"], "declared": {"model": "model-b"}})
    kinds = {finding["kind"] for finding in _drift(client)["findings"]}
    assert "model_changed" in kinds


# --- the connection file -----------------------------------------------------

def test_the_connection_file_describes_exactly_the_calls_an_agent_can_make(app):
    spec = TestClient(app, base_url="http://127.0.0.1").get("/api/v1/external/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    assert set(spec["paths"]) == {
        "/api/v1/external/screen", "/api/v1/external/runs", "/api/v1/external/runs/start",
        "/api/v1/external/runs/{goal_id}/heartbeat", "/api/v1/external/runs/{goal_id}/finish",
        "/api/v1/external/approvals/{approval_id}"}
    # every call it describes exists: without an access key the answer is
    # "who are you", never "no such address" or "wrong method"
    stranger = TestClient(app, base_url="http://127.0.0.1")
    for path, operations in spec["paths"].items():
        address = path.replace("{goal_id}", "1").replace("{approval_id}", "1")
        for method in operations:
            assert stranger.request(method.upper(), address, json={}).status_code == 401, (method, path)


@pytest.mark.parametrize("address", [
    "/api/v1/external/memory/ingest", "/api/v1/external/memory/recall", "/api/v1/external/execute",
    "/api/v1/external/executions/1/commit", "/api/v1/external/runtime/evaluate",
    "/api/v1/external/red-team/1/cases", "/api/v1/external/red-team/1/results"])
def test_calls_this_product_does_not_offer_are_not_served(app, agent, address):
    assert agent.post(address, json={}).status_code in (404, 405)


@pytest.mark.parametrize("path", ["/api/v1/external/runs", "/api/v1/external/runs/{goal_id}/finish"])
def test_the_connection_file_publishes_the_two_drift_fields(app, path):
    spec = TestClient(app, base_url="http://127.0.0.1").get("/api/v1/external/openapi.json").json()
    properties = spec["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]
    assert properties["tools"]["type"] == "array" and properties["tools"]["items"] == {"type": "string"}
    assert set(properties["declared"]["properties"]) == {"version", "config_digest", "model"}


# --- the link to the agent's platform record ---------------------------------

def test_an_agent_can_be_linked_to_its_platform_record(client):
    assert _enroll(client, platform="foundry", external_ref="foundry:helpdesk").status_code == 201
    (row,) = client.get("/api/v1/external-agents").json()["agents"]
    assert row["external_ref"] == "foundry:helpdesk" and row["platform_label"] == "Microsoft Foundry"
    assert client.get("/api/v1/external-agents/helpdesk").json()["external_ref"] == "foundry:helpdesk"


def test_updating_an_agent_keeps_its_link_unless_one_is_given(client):
    _enroll(client, external_ref="copilot_studio:5f0c")
    assert _enroll(client, max_dollars=10).status_code == 201
    assert client.get("/api/v1/external-agents/helpdesk").json()["external_ref"] == "copilot_studio:5f0c"
    assert _enroll(client, external_ref="copilot_studio:77aa").status_code == 201
    assert client.get("/api/v1/external-agents/helpdesk").json()["external_ref"] == "copilot_studio:77aa"
    assert _enroll(client, external_ref="").status_code == 201
    assert client.get("/api/v1/external-agents/helpdesk").json()["external_ref"] == ""


@pytest.mark.parametrize("bad", ["helpdesk", "foundry:", ":helpdesk", "Foundry:helpdesk", "foundry:help desk",
                                 "foundry:help\ndesk", "f" * 41 + ":x"])
def test_a_malformed_link_is_refused_and_the_agent_is_not_enrolled(client, bad):
    refused = _enroll(client, external_ref=bad)
    assert refused.status_code == 400 and "external_ref" in refused.json()["detail"]
    assert client.get("/api/v1/external-agents").json()["agents"] == []


def test_two_agents_cannot_claim_the_same_platform_record(client):
    assert _enroll(client, external_ref="foundry:helpdesk").status_code == 201
    refused = _enroll(client, "second", external_ref="foundry:helpdesk")
    assert refused.status_code == 400 and "already linked" in refused.json()["detail"]
    assert [row["id"] for row in client.get("/api/v1/external-agents").json()["agents"]] == ["helpdesk"]
    # platform checks match without regard to capitals, so a respelling is the same record
    assert _enroll(client, "second", external_ref="foundry:HelpDesk").status_code == 400
    # the holder itself can be saved again with the link it already has
    assert _enroll(client, external_ref="foundry:helpdesk").status_code == 201


@pytest.mark.parametrize("platform", ["copilot", "m365_copilot", "foundry", "servicenow", "workday", "bedrock", "custom"])
def test_the_platforms_this_product_is_deployed_for_can_be_chosen(client, platform):
    assert _enroll(client, platform=platform).status_code == 201


# --- the roster page ----------------------------------------------------------

def test_the_roster_page_only_calls_addresses_this_product_serves(client):
    page = client.get("/external-agents").text
    for absent in ("/api/v1/people/assignable", "/api/v1/departments", "/api/v1/tools", "data_scopes"):
        assert absent not in page
    assert 'name="external_ref"' in page and 'name="owner"' in page and 'name="department"' in page
    assert 'download="second-shift-connection.json"' in page
    for other_customer in ("Salesforce Named Credential", "Bedrock action group", "lessons shared"):
        assert other_customer not in page


def test_the_page_offers_no_switch_when_governance_is_off(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    page = client.get("/external-agents").text
    assert "turned off" in page and "mg-on" not in page
