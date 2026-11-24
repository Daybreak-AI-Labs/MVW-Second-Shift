"""The My agents page: who sees which agents, and what each card shows.

Hermetic. People sign in as in ``signin_kit``, with a token that carries the
claims the test needs (a verified email, an Entra object id).
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from maverick import external_agents as xa
from tests.new import signin_kit as kit

OID = "11111111-2222-3333-4444-555555555555"
OTHER_OID = "99999999-2222-3333-4444-555555555555"


@pytest.fixture(scope="module")
def signing_key():
    return kit.new_key()


@pytest.fixture
def installation(tmp_path, monkeypatch, request, signing_key):
    stop = kit.start(tmp_path, monkeypatch, request, signing_key)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    yield tmp_path
    stop()


@pytest.fixture
def app():
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def person(installation, app, signing_key):
    """A client signed in with the role named ``role`` and the given claims."""
    def client(role: str = "viewer", **claims) -> TestClient:
        token = kit.mint(signing_key, role, **claims)
        return TestClient(app, base_url="http://127.0.0.1",
                          headers={"Origin": "http://127.0.0.1", "Authorization": "Bearer " + token})
    return client


def _enroll(agent_id="helpdesk", owner="jo@example.com", **fields):
    return xa.enroll(agent_id, "custom", description=fields.pop("description", "Help desk agent"),
                     owner=owner, **fields)


def _page(client: TestClient):
    return client.get("/my-agents")


def test_an_owner_sees_their_agent_by_verified_email(installation, person):
    _enroll()
    response = _page(person("viewer", email="Jo@Example.com", email_verified=True))
    assert response.status_code == 200
    assert "Help desk agent" in response.text
    assert "/external-agents/helpdesk" in response.text


def test_an_unverified_email_sees_nothing(installation, person):
    _enroll()
    for claims in ({"email": "jo@example.com"}, {"email": "jo@example.com", "email_verified": False}):
        response = _page(person("viewer", **claims))
        assert "Help desk agent" not in response.text
        assert "cannot tell who you are" in response.text


def test_a_name_is_never_a_match(installation, person):
    _enroll(owner="Jo Smith")
    response = _page(person("viewer", name="Jo Smith", preferred_username="Jo Smith", email="x@example.com",
                            email_verified=True))
    assert "Help desk agent" not in response.text
    assert "do not own any agents" in response.text


def test_object_id_matches_without_an_email(installation, person):
    _enroll(owner="jo@example.com", owner_object_id=OID)
    assert "Help desk agent" in _page(person("viewer", oid=OID)).text


def test_a_different_object_id_overrides_a_matching_email(installation, person):
    _enroll(owner="jo@example.com", owner_object_id=OID)
    response = _page(person("viewer", email="jo@example.com", email_verified=True, oid=OTHER_OID))
    assert "Help desk agent" not in response.text


def test_someone_else_does_not_see_the_agent(installation, person):
    _enroll()
    _enroll("other", owner="kim@example.com", description="Kim's agent")
    text = _page(person("viewer", email="kim@example.com", email_verified=True)).text
    assert "Kim&#39;s agent" in text and "Help desk agent" not in text


def test_no_agents_explains(installation, person):
    response = _page(person("viewer", email="nobody@example.com", email_verified=True))
    assert response.status_code == 200
    assert "do not own any agents" in response.text


def test_names_are_escaped(installation, person):
    _enroll(description="<script>alert(1)</script>")
    text = _page(person("viewer", email="jo@example.com", email_verified=True)).text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_a_viewer_gets_a_read_only_page_that_names_administrators(installation, person):
    _enroll()
    text = _page(person("viewer", email="jo@example.com", email_verified=True)).text
    assert "Only an administrator can change" in text
    assert "Pause or resume" not in text
    assert 'href="/approvals"' not in text


def test_an_administrator_owner_is_not_told_it_is_read_only(installation, person):
    _enroll()
    text = _page(person("admin", email="jo@example.com", email_verified=True)).text
    assert "Only an administrator can change" not in text
    assert "Read only for you" not in text
    assert "Pause or resume" in text


def test_spend_against_the_limit(installation, person):
    _enroll(max_dollars=100.0)
    with xa._sidecar_locked():
        sidecar = xa._load_sidecar()
        sidecar["helpdesk"].update(period="monthly", period_key=xa._month_key(), period_spent=85.0)
        xa._save_sidecar(sidecar)
    text = _page(person("viewer", email="jo@example.com", email_verified=True)).text
    match = re.search(r'data-fact="spend">(.*?)</dd>', text, re.S)
    assert match and "85%" in match.group(1) and "Near the limit" in match.group(1)
    assert "Spending near the limit" in text


def test_key_expiry_is_shown(installation, person):
    _enroll(expires_days=3)
    text = _page(person("viewer", email="jo@example.com", email_verified=True)).text
    match = re.search(r'data-fact="key">(.*?)</dd>', text, re.S)
    assert match and "Ends" in match.group(1)
    assert "Access key ending" in text


def test_waiting_requests_are_counted(installation, person):
    from maverick.world_model import open_world

    _enroll()
    open_world().create_approval("external:helpdesk:send_email", risk="high", detail="x",
                                 requested_by="agent:helpdesk", provenance="external_agents")
    open_world().create_approval("external:other:send_email", risk="high", detail="x",
                                 requested_by="agent:other", provenance="external_agents")
    text = _page(person("viewer", email="jo@example.com", email_verified=True)).text
    match = re.search(r'data-fact="requests">(.*?)</dd>', text, re.S)
    assert match and "<strong>1</strong> waiting" in match.group(1)
    assert "Only an approver can decide them" in match.group(1)
    approver = _page(person("approver", email="jo@example.com", email_verified=True)).text
    assert 'href="/approvals"' in approver


def test_never_heard_from_agent_is_added_level(installation, person):
    _enroll()
    text = _page(person("viewer", email="jo@example.com", email_verified=True)).text
    assert "not heard from yet" in text
    assert "Added" in text


def test_the_page_runs_no_check(installation, person, monkeypatch):
    from maverick import agent_drift, agent_watch

    _enroll()

    def boom(*a, **k):
        raise AssertionError("a check ran")

    for module, names in ((agent_drift, ("check", "check_all", "approve_baseline")),
                          (agent_watch, ("sync",))):
        for name in names:
            monkeypatch.setattr(module, name, boom)
    assert _page(person("viewer", email="jo@example.com", email_verified=True)).status_code == 200


def test_an_unreadable_roster_is_not_shown_as_empty(installation, person, monkeypatch):
    def broken(*a, **k):
        raise OSError("no")

    monkeypatch.setattr(xa, "roster", broken)
    response = _page(person("viewer", email="jo@example.com", email_verified=True))
    assert response.status_code == 503
    assert "could not be read" in response.text


def test_sign_in_is_required(installation, app):
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/my-agents").status_code in (401, 403)


def test_the_page_is_in_the_navigation_registry():
    from maverick_dashboard import ui_visibility

    page = ui_visibility.page_for("/my-agents")
    assert page and page["floor"] == "view" and page["default"] == "view"
