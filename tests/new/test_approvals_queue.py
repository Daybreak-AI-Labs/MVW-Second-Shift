"""The approvals queue: a person approves or rejects what an agent has parked."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


@pytest.fixture
def world(app):
    from maverick_dashboard._shared import _world

    return _world()


def test_approval_queue_scans_a_repeated_display_label_once_per_render(monkeypatch):
    from types import SimpleNamespace

    from maverick.safety import secret_detector
    from maverick_dashboard.app import _approval_queue_context

    read = []

    class Pattern:
        def finditer(self, text):
            read.append(text)
            return iter(())

    monkeypatch.setattr(secret_detector, "_PATTERNS", [("test", Pattern())])
    rows = [SimpleNamespace(id=i, provenance="", action="Review", scope="Object", detail="")
            for i in range(3)]
    for _ in range(2):
        context = _approval_queue_context(rows)
        assert list(context["approval_actions"].values()) == ["Review"] * 3
    assert read.count("Review") == 2


def test_postgres_queue_opens_its_encryption_key_once_per_read(records_in_postgres, monkeypatch):
    from hashlib import sha256

    from maverick import crypto_at_rest
    from maverick.world_model_backends.postgres import PostgresWorldModel

    key = bytes(range(32))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + sha256(key).hexdigest())
    world = PostgresWorldModel(dsn=records_in_postgres)
    try:
        for label in ("First", "Second", "Third"):
            world.create_approval(label, scope="Object", detail="Details")

        loaded = []
        original = crypto_at_rest._load_existing_key

        def tracked():
            loaded.append(1)
            return original()

        monkeypatch.setattr(crypto_at_rest, "_load_existing_key", tracked)
        for _ in range(2):
            rows = world.pending_approvals()
            assert [(row.action, row.scope, row.detail) for row in rows] == [
                (label, "Object", "Details") for label in ("First", "Second", "Third")]
        assert loaded == [1, 1]
    finally:
        world.close()


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


def _park(agent, tool="send_contract"):
    parked = agent.post("/api/v1/external/screen", json={"tool": tool, "risk": "high"}).json()
    assert parked["requires_approval"] is True, parked
    return parked


def _poll(agent, parked):
    return agent.get(f"/api/v1/external/approvals/{parked['approval_id']}",
                     params={"binding_sha256": parked["approval_binding_sha256"]}).json()


def _card(**fields):
    from maverick.approval_cards import build_approval_card

    values = dict(
        action="records.update", summary="Approve the reviewed customer change",
        target_label="<script>target</script>",
        target={"page": "https://customer.example/settings", "selector": "#save"},
        parameters={"note": "never-render-this"}, parameter_summary=["Save the reviewed setting once"],
        actor="user:alice", workspace="tenant-a", role="operator",
        authority_versions={"role_revision": "role-v1"}, input_versions={"page_revision": "page-v1"},
        credential_versions={"session_sha256": "a" * 64}, budget={"currency": "USD", "maximum": 0.25},
        expires_at=time.time() + 300, known_effects=["Changes the reviewed customer setting."],
        unresolved_assumptions=["The page may send a notification."],
        before="The setting is unchanged.", after="The reviewed setting is saved.", irreversible=True)
    values.update(fields)
    return build_approval_card(**values)


# --- an outside agent's parked action, end to end ----------------------------

def test_a_parked_action_waits_in_the_queue_and_goes_ahead_once_a_person_approves(client, agent):
    parked = _park(agent)
    assert _poll(agent, parked)["status"] == "pending"
    listed = client.get("/api/v1/approvals").json()
    (row,) = listed["approvals"]
    assert row["id"] == parked["approval_id"] and listed["private_count"] == 0
    assert client.get("/api/v1/approvals/waiting-count").json() == {"waiting": 1}

    page = client.get("/approvals")
    assert page.status_code == 200 and page.headers["cache-control"] == "private, no-store"
    assert f'id="approval-{row["id"]}"' in page.text and "Outside agent" in page.text
    assert "1 waiting" in page.text

    binding = {"X-Second-Shift-Approval-Binding": parked["approval_binding_sha256"]}
    approved = client.post(f"/api/v1/approvals/{row['id']}/approve", json={"acknowledged": True}, headers=binding)
    assert approved.status_code == 204, approved.text
    assert approved.headers["X-Second-Shift-Approval-State"] == "approved"
    assert _poll(agent, parked)["status"] == "approved"
    assert client.get("/api/v1/approvals").json()["approvals"] == []
    assert client.get("/api/v1/approvals/waiting-count").json() == {"waiting": 0}


def test_a_rejected_action_does_not_go_ahead(client, agent):
    parked = _park(agent)
    rejected = client.post(f"/api/v1/approvals/{parked['approval_id']}/deny", json={"reason": "Not this quarter"})
    assert rejected.status_code == 204, rejected.text
    assert rejected.headers["X-Second-Shift-Approval-State"] == "denied"
    assert _poll(agent, parked)["status"] == "denied"


def test_a_high_risk_approval_needs_the_person_to_acknowledge_it(client, agent):
    parked = _park(agent)
    binding = {"X-Second-Shift-Approval-Binding": parked["approval_binding_sha256"]}
    bare = client.post(f"/api/v1/approvals/{parked['approval_id']}/approve", json={}, headers=binding)
    assert bare.status_code in (400, 409, 422), bare.text
    assert _poll(agent, parked)["status"] == "pending"


def test_an_approval_must_name_the_exact_request_the_person_saw(client, agent):
    parked = _park(agent)
    address = f"/api/v1/approvals/{parked['approval_id']}/approve"
    missing = client.post(address, json={"acknowledged": True})
    assert missing.status_code == 409
    stale = client.post(address, json={"acknowledged": True}, headers={"X-Second-Shift-Approval-Binding": "b" * 64})
    assert stale.status_code == 409
    assert _poll(agent, parked)["status"] == "pending"


def test_a_decision_from_another_site_is_refused(app, client, agent):
    parked = _park(agent)
    elsewhere = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://elsewhere.example"})
    assert elsewhere.post(f"/api/v1/approvals/{parked['approval_id']}/deny", json={}).status_code == 403
    assert _poll(agent, parked)["status"] == "pending"


def test_the_agent_cannot_decide_its_own_request(agent):
    parked = _park(agent)
    assert agent.post(f"/api/v1/approvals/{parked['approval_id']}/approve",
                      json={"acknowledged": True}).status_code in (401, 403)
    assert _poll(agent, parked)["status"] == "pending"


# --- what the person deciding is shown ----------------------------------------

def _park_with(agent, detail):
    parked = agent.post("/api/v1/external/screen", json={"tool": "refund_guest", "risk": "high", "detail": detail}).json()
    assert parked["requires_approval"] is True, parked
    return parked


def test_the_person_deciding_sees_what_the_agent_said_it_would_do(client, agent):
    _park_with(agent, "Refund 450 USD to reservation 81234 <b>now</b>")
    page = client.get("/approvals").text
    assert "The agent says: Refund 450 USD to reservation 81234 &lt;b&gt;now&lt;/b&gt;" in page
    assert "<b>now</b>" not in page
    assert ">Refund guest</h2>" in page and 'href="/external-agents/helpdesk"' in page


def test_a_long_description_is_shortened_and_a_secret_in_it_is_removed(client, agent):
    secret = "sk-ant-" + "a" * 40  # pragma: allowlist secret
    _park_with(agent, f"Use key {secret} to refund. " + "word " * 300)
    page = client.get("/approvals").text
    assert secret not in page
    assert "(shortened)" in page and page.count("word ") < 120


def test_the_description_can_be_kept_out_of_the_request(client, agent, tmp_path, monkeypatch):
    from maverick import config

    settings = tmp_path / "config.toml"
    settings.write_text("[external_agents]\nshow_request_detail = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(settings))
    config.reset_config_cache()
    try:
        _park_with(agent, "Refund 450 USD to reservation 81234")
        page = client.get("/approvals").text
        assert "Refund guest" in page and "81234" not in page and "The agent says" not in page
    finally:
        monkeypatch.delenv("MAVERICK_CONFIG")
        config.reset_config_cache()


def test_changing_the_description_makes_it_a_different_request(agent):
    first = _park_with(agent, "Refund 450 USD to reservation 81234")
    second = _park_with(agent, "Refund 9000 USD to reservation 81234")
    assert first["approval_binding_sha256"] != second["approval_binding_sha256"]


# --- the page ----------------------------------------------------------------

def test_an_empty_queue_says_nothing_is_waiting(client):
    page = client.get("/approvals").text
    assert "Nothing is waiting" in page and "0 waiting" in page
    assert "data-ap-decide" not in page.split("<script")[0]


def test_text_from_an_agent_is_shown_as_text_never_as_markup(client, world):
    world.create_approval("<img src=x onerror=alert(1)>", risk="high", scope="<b>scope</b>",
                          detail="<script>alert(2)</script>")
    page = client.get("/approvals").text
    for raw in ("<img src=x", "<b>scope</b>", "<script>alert(2)</script>"):
        assert raw not in page
    assert "&lt;b&gt;scope&lt;/b&gt;" in page and "&lt;script&gt;alert(2)&lt;/script&gt;" in page


def test_a_reviewed_request_shows_its_summary_and_target_but_not_its_parameters(client, world):
    from maverick.approval_cards import encode_approval_detail

    card = _card()
    approval_id = world.create_approval("records.update", risk="high", scope="#save", detail=encode_approval_detail(card))
    page = client.get("/approvals").text
    assert "Approve the reviewed customer change" in page
    assert "&lt;script&gt;target&lt;/script&gt;" in page and "<script>target</script>" not in page
    assert "never-render-this" not in page
    assert "cannot be reversed" in page
    assert f'data-binding="{card["binding_sha256"]}"' in page
    address = f"/api/v1/approvals/{approval_id}/approve"
    assert client.post(address, json={"acknowledged": True}).status_code == 409
    current = client.post(address, json={"acknowledged": True},
                          headers={"X-Second-Shift-Approval-Binding": card["binding_sha256"]})
    assert current.status_code == 204, current.text
    assert world.get_approval(approval_id).status == "approved"


def test_an_expired_request_cannot_be_approved_from_the_page(client, world):
    from maverick.approval_cards import encode_approval_detail

    card = _card(expires_at=time.time() + 1)
    approval_id = world.create_approval("records.update", risk="high", scope="#save", detail=encode_approval_detail(card))
    time.sleep(1.1)
    page = client.get("/approvals").text
    assert "Expired" in page and "can no longer be approved" in page
    refused = client.post(f"/api/v1/approvals/{approval_id}/approve", json={"acknowledged": True},
                          headers={"X-Second-Shift-Approval-Binding": card["binding_sha256"]})
    assert refused.status_code == 409
    assert world.get_approval(approval_id).status == "pending"


def test_the_navigation_offers_approvals(client):
    assert 'href="/approvals"' in client.get("/external-agents").text


def test_calls_the_queue_does_not_offer_are_not_served(client, world):
    approval_id = world.create_approval("records.update", risk="low", scope="x", detail="y")
    for action in ("undo", "revise", "claim", "release"):
        assert client.post(f"/api/v1/approvals/{approval_id}/{action}", json={}).status_code in (404, 405)


def test_pending_progress_does_not_load_each_approval_again(client, world, monkeypatch):
    for index in range(4):
        world.create_approval(f"external:helpdesk:work_{index}", risk="medium",
                              provenance="external_agents", requested_by="agent:helpdesk")
    original = world.approval_state
    reads = []

    def counted(approval_id):
        reads.append(approval_id)
        return original(approval_id)

    monkeypatch.setattr(world, "approval_state", counted)
    result = client.get("/approvals")
    assert result.status_code == 200
    assert result.text.count("One approval is needed.") == 4
    assert not reads
