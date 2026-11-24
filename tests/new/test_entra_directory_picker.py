"""The owner picker: the people search route and the add-agent form's use of it.

Signed in as in ``signin_kit`` (one person per role, every request through the
real routes); Microsoft Graph is ``entra_kit.Graph``."""
from __future__ import annotations

import logging

import httpx
import pytest

from tests.new import entra_kit as kit
from tests.new import signin_kit as sk
from tests.new.entra_kit import PEOPLE, Graph
from tests.new.signin_kit import ROLES

OID = PEOPLE["erin"]


@pytest.fixture(scope="module")
def signing_key():
    return sk.new_key()


@pytest.fixture
def installation(tmp_path, monkeypatch, request, signing_key):
    from maverick import agent_watch, entra_directory

    stop = sk.start(tmp_path, monkeypatch, request, signing_key)
    monkeypatch.setenv("GRAPH_TENANT", kit.TENANT)
    monkeypatch.setenv("GRAPH_CLIENT", kit.CLIENT)
    monkeypatch.setenv("GRAPH_SECRET", kit.SECRET)
    monkeypatch.delenv("MAVERICK_ENTRA_DIRECTORY", raising=False)
    kit.write_config(tmp_path)
    entra_directory.reset_cache()
    agent_watch._TOKENS.clear()
    yield tmp_path
    entra_directory.reset_cache()
    agent_watch._TOKENS.clear()
    stop()


@pytest.fixture
def graph(installation, monkeypatch) -> Graph:
    g = kit.serve(monkeypatch, Graph())
    g.users = [kit.user_row("Erin Quinn", "erin@example.com", OID, "Head of Finance"),
               kit.user_row("Eric Lund", None, PEOPLE["frank"], None, upn="eric@corp.example.com")]
    return g


@pytest.fixture
def person(installation, signing_key):
    from maverick_dashboard.app import app

    def client(role: str):
        return sk.client_for(app, signing_key, role)
    return client


def _turn_off(path) -> None:
    kit.write_config(path, body="")


# ------------------------------------------------------------- the route


@pytest.mark.parametrize("role", ROLES)
def test_only_an_administrator_may_search_and_nobody_else_triggers_a_lookup(person, graph, role):
    answer = person(role).get("/api/v1/directory/people?q=er")
    if role == "admin":
        assert answer.status_code == 200
    else:
        assert answer.status_code == 403
        assert graph.requests == []


def test_a_search_returns_only_a_name_an_email_an_object_id_and_a_job_title(person, graph):
    answer = person("admin").get("/api/v1/directory/people", params={"q": "er"})
    assert answer.status_code == 200
    body = answer.json()
    assert body["enabled"] is True
    assert body["people"] == [
        {"display_name": "Eric Lund", "email": "eric@corp.example.com", "object_id": PEOPLE["frank"], "job_title": ""},
        {"display_name": "Erin Quinn", "email": "erin@example.com", "object_id": OID, "job_title": "Head of Finance"}]
    assert "Building 4" not in answer.text and "555" not in answer.text and kit.TOKEN not in answer.text


def test_a_short_or_missing_query_finds_nobody_and_asks_nobody(person, graph):
    admin = person("admin")
    for query in ("", "e", " "):
        assert admin.get("/api/v1/directory/people", params={"q": query}).json()["people"] == []
    assert admin.get("/api/v1/directory/people").json()["people"] == []
    assert graph.requests == []


def test_with_the_directory_off_the_route_says_so_and_asks_nobody(person, graph, installation):
    _turn_off(installation)
    body = person("admin").get("/api/v1/directory/people?q=erin").json()
    assert body == {"enabled": False, "people": []} and graph.requests == []


def test_a_search_that_fails_answers_in_plain_words_without_microsoft_text_or_secrets(person, graph, caplog):
    graph.script = [("/users", httpx.Response(403, json={"error": {"message": f"denied {kit.TOKEN}"}}))]
    with caplog.at_level(logging.DEBUG):
        answer = person("admin").get("/api/v1/directory/people?q=erin")
    assert answer.status_code == 503 and "email" in answer.json()["detail"]
    assert kit.TOKEN not in answer.text + caplog.text and kit.SECRET not in answer.text + caplog.text


def test_the_route_is_read_only(person, graph):
    admin = person("admin")
    assert admin.post("/api/v1/directory/people", json={}).status_code == 405
    assert admin.delete("/api/v1/directory/people").status_code == 405


# --------------------------------------------------------- the add form


def _add(client, **fields):
    return client.post("/api/v1/external-agents", json={"id": "helpdesk", "platform": "custom", **fields})


def test_a_chosen_person_is_stored_with_their_email_and_object_id(person, graph):
    admin = person("admin")
    assert _add(admin, owner="erin@example.com", owner_object_id=OID.upper()).status_code == 201
    row, = [a for a in admin.get("/api/v1/external-agents").json()["agents"] if a["id"] == "helpdesk"]
    assert row["owner"] == "erin@example.com" and row["owner_object_id"] == OID


def test_a_typed_email_still_works_with_the_directory_off(person, graph, installation):
    _turn_off(installation)
    admin = person("admin")
    assert _add(admin, owner="someone@example.com").status_code == 201
    row, = [a for a in admin.get("/api/v1/external-agents").json()["agents"] if a["id"] == "helpdesk"]
    assert row["owner"] == "someone@example.com" and row["owner_object_id"] == ""


def test_an_object_id_that_is_not_one_is_refused_and_one_without_an_owner_is_not_kept(person, graph):
    admin = person("admin")
    assert _add(admin, owner="a@example.com", owner_object_id="not-an-id").status_code == 422
    assert _add(admin, owner="", owner_object_id=OID).status_code == 201
    row, = [a for a in admin.get("/api/v1/external-agents").json()["agents"] if a["id"] == "helpdesk"]
    assert row["owner_object_id"] == ""
    assert _add(person("viewer"), owner="a@example.com").status_code == 403


def test_the_page_offers_the_picker_only_to_an_administrator_with_the_directory_on(person, graph, installation):
    assert 'id="xa-owner-list"' in person("admin").get("/external-agents").text
    assert 'id="xa-owner-list"' not in person("operator").get("/external-agents").text
    _turn_off(installation)
    page = person("admin").get("/external-agents").text
    assert 'id="xa-owner-list"' not in page and 'name="owner"' in page  # a typed email remains
