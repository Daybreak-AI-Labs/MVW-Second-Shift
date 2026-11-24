"""Switching an agent off on its own platform, where the platform documents a
way: Microsoft Entra Agent ID only. Every request is answered by a stand-in
(``httpx.MockTransport``); nothing talks to Microsoft."""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager

import httpx
import pytest
from fastapi.testclient import TestClient

from maverick import agent_watch as watch
from maverick import agent_watch_microsoft  # noqa: F401 -- registers the built-in checks
from maverick import external_agents as xa

TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
CLIENT = "00001111-aaaa-2222-bbbb-3333cccc4444"
#: Shaped like real credentials so the secret checks mean something.
SECRET = "Zx8~Q.fake-client-secret_4hT9"  # pragma: allowlist secret
TOKEN = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."  # pragma: allowlist secret
         "eyJhdWQiOiJmYWtlIiwiaXNzIjoiZmFrZSJ9.c2lnbmF0dXJlLW5vdC1yZWFs")  # pragma: allowlist secret
IDENTITY = "1b7313c4-05d0-4a08-88e3-7b76c003a0a2"
AGENT = "guest-help"
PATCH_URL = f"https://graph.microsoft.com/v1.0/servicePrincipals/{IDENTITY}/microsoft.graph.agentIdentity"
SWITCH = f"/api/v1/external-agents/{AGENT}/platform-switch"

_ENTRA = ('[agent_watch]\nenable = true\nplatforms = ["entra_agent_id"]\n'
          '[agent_watch.entra_agent_id]\ntenant_id_env = "WATCH_TENANT"\nclient_id_env = "WATCH_CLIENT"\n'
          'client_secret_env = "WATCH_SECRET"\n{extra}')


class Graph:
    """A stand-in for the sign-in endpoint and Graph. ``patch`` answers the
    write; every request is kept, and a request to anything else fails the
    test."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.patch: object = httpx.Response(204)
        self.unexpected: list[str] = []
        self.on_patch = lambda: None

    def answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599,
                                             "access_token": TOKEN})
        if request.method == "PATCH" and str(request.url) == PATCH_URL:
            self.on_patch()
            if isinstance(self.patch, Exception):
                raise self.patch
            return self.patch
        self.unexpected.append(f"{request.method} {request.url}")
        return httpx.Response(404, json={"error": {"code": "NotFound"}})

    def writes(self) -> list[httpx.Request]:
        return [request for request in self.requests if request.method not in ("GET", "POST")]


@pytest.fixture
def graph(monkeypatch):
    from maverick.tools import _ssrf
    service = Graph()

    @contextmanager
    def client(url, timeout=None):
        with httpx.Client(transport=httpx.MockTransport(service.answer), timeout=timeout) as value:
            yield value

    monkeypatch.setattr(_ssrf, "safe_client", client)
    yield service
    assert service.unexpected == []
    assert all(request.url.scheme == "https" for request in service.requests)


class Rows(list):
    """Audit rows, and the kinds on record at the moment each write arrived."""

    before_write: list[list[str]]


@pytest.fixture
def audit_rows(monkeypatch, graph):
    import maverick.audit as audit_pkg
    rows = Rows()
    seen_before_write: list[list[str]] = []

    def record(kind, *, agent="system", goal_id=None, **payload):
        rows.append({"kind": str(kind), "agent": agent, **payload})
        return True

    monkeypatch.setattr(audit_pkg, "record", record)
    graph.on_patch = lambda: seen_before_write.append([row["kind"] for row in rows])
    rows.before_write = seen_before_write
    return rows


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    monkeypatch.setenv("WATCH_TENANT", TENANT)
    monkeypatch.setenv("WATCH_CLIENT", CLIENT)
    monkeypatch.setenv("WATCH_SECRET", SECRET)
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    monkeypatch.setattr(watch, "_TOKENS", {})
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _configure(tmp_path, extra: str = "allow_switch_off = true\n") -> None:
    (tmp_path / "config.toml").write_text(_ENTRA.format(extra=extra), encoding="utf-8")
    from maverick import config
    config.reset_config_cache()


@pytest.fixture
def client(tmp_path):
    from maverick_dashboard.app import app
    _configure(tmp_path)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def _enroll(client, ref: str | None = f"entra_agent_id:{IDENTITY}", agent_id: str = AGENT) -> None:
    r = client.post("/api/v1/external-agents", json={"id": agent_id, "platform": "custom",
                                                     "owner": "ops@example.com"})
    assert r.status_code == 201, r.text
    if ref is not None:
        path = xa.registry_path()
        entries = json.loads(path.read_text(encoding="utf-8"))
        entries[agent_id]["external_ref"] = ref
        path.write_text(json.dumps(entries), encoding="utf-8")


def _as(monkeypatch, role: str) -> list[str]:
    from fastapi import HTTPException

    from maverick_dashboard import agent_watch_api, rbac
    asked: list[str] = []

    def require(_request, permission):
        asked.append(permission)
        if permission not in rbac.permissions_for(role):
            raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(agent_watch_api, "require_permission", require)
    return asked


def _files() -> dict[str, str]:
    """Everything Second Shift keeps about agents, as text."""
    from maverick import agent_drift
    return {path.name: path.read_text(encoding="utf-8")
            for path in (xa.registry_path(), watch.store_path(), agent_drift.store_path())
            if path.exists()}


def _off(client, **body):
    return client.post(SWITCH, json={"action": "off", "confirmed": True, **body})


# ------------------------------------------------------------------ refusals

def test_it_is_refused_unless_the_platforms_settings_allow_it(client, graph, tmp_path):
    _enroll(client)
    for extra in ("", "allow_switch_off = false\n"):
        _configure(tmp_path, extra)
        r = _off(client)
        assert r.status_code == 409
        assert "allow_switch_off" in r.json()["detail"] and "AgentIdentity.EnableDisable.All" in r.json()["detail"]
    assert graph.requests == []


def test_a_setting_that_is_not_true_or_false_is_refused_not_guessed(client, graph, tmp_path):
    _enroll(client)
    _configure(tmp_path, 'allow_switch_off = "yes"\n')
    r = _off(client)
    assert r.status_code == 409 and "true or false" in r.json()["detail"]
    assert graph.requests == []
    row, = [row for row in watch.status()["platforms"] if row["name"] == "entra_agent_id"]
    assert row["ready"] is False and "true or false" in row["problem"]


@pytest.mark.parametrize("role", ["viewer", "auditor", "responder", "approver", "operator"])
def test_only_an_administrator_may_switch_an_agent_off(client, graph, monkeypatch, role):
    _enroll(client)
    asked = _as(monkeypatch, role)
    assert _off(client).status_code == 403
    assert asked == ["admin"] and graph.requests == []


def test_an_administrator_is_asked_for_and_allowed(client, graph, monkeypatch):
    _enroll(client)
    asked = _as(monkeypatch, "admin")
    assert _off(client).status_code == 200 and "admin" in asked


def test_reading_what_could_be_done_needs_only_the_view_permission(client, graph, monkeypatch):
    _enroll(client)
    asked = _as(monkeypatch, "viewer")
    assert client.get(SWITCH).status_code == 200 and asked == ["view"]


def test_an_agent_with_no_platform_link_cannot_be_switched_off(client, graph):
    _enroll(client, ref=None)
    r = _off(client)
    assert r.status_code == 409 and "not linked to a platform" in r.json()["detail"]
    assert graph.requests == []


def test_an_agent_that_is_not_enrolled_is_not_found(client, graph):
    r = client.post("/api/v1/external-agents/nobody/platform-switch", json={"action": "off", "confirmed": True})
    assert r.status_code == 404 and graph.requests == []
    assert client.get("/api/v1/external-agents/nobody/platform-switch").status_code == 404


def test_it_is_not_found_while_outside_agent_governance_is_off(client, graph, monkeypatch):
    _enroll(client)
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert _off(client).status_code == 404 and client.get(SWITCH).status_code == 404
    assert graph.requests == []


@pytest.mark.parametrize("platform, words", [
    ("copilot_studio", "signed-in administrator"),
    ("workday", "Agent Management Hub"),
    ("servicenow", "AI Agent Studio"),
    ("foundry", "Foundry portal"),
])
def test_a_platform_with_no_documented_way_says_so_and_what_the_administrator_does(
        client, graph, platform, words):
    _enroll(client, ref=f"{platform}:some-id")
    r = _off(client)
    assert r.status_code == 409
    assert words in r.json()["detail"]
    assert graph.requests == []
    offered = client.get(SWITCH).json()
    assert offered["supported"] is False and words in offered["reason"]


def test_an_unknown_platform_is_refused(client, graph):
    _enroll(client, ref="mystery:abc")
    assert _off(client).status_code == 409 and graph.requests == []


@pytest.mark.parametrize("ref", ["entra_agent_id:not-a-guid", "entra_agent_id:../../me",
                                 f"entra_agent_id:{IDENTITY}/x", f"entra_agent_id:{IDENTITY}?a=b"])
def test_an_id_that_is_not_an_identity_id_is_never_put_in_an_address(client, graph, ref):
    _enroll(client, ref=ref)
    assert _off(client).status_code == 409
    assert graph.requests == []


def test_it_needs_a_confirmation_and_takes_nothing_but_the_agent_from_the_caller(client, graph):
    _enroll(client)
    assert client.post(SWITCH, json={"action": "off"}).status_code == 422
    assert client.post(SWITCH, json={"action": "off", "confirmed": False}).status_code == 422
    assert client.post(SWITCH, json={"action": "delete", "confirmed": True}).status_code == 422
    for extra in ({"url": "https://evil.example/"}, {"id": "other"}, {"platform": "workday"},
                  {"external_id": "x"}, {"body": {"accountEnabled": False}}):
        assert _off(client, **extra).status_code == 422
    assert graph.requests == []


# ------------------------------------------------------------------- success

def test_it_sends_exactly_the_documented_request(client, graph, audit_rows):
    _enroll(client)
    r = _off(client)
    assert r.status_code == 200, r.text
    write, = graph.writes()
    # PATCH /servicePrincipals/{id}/microsoft.graph.agentIdentity, answered 204 No Content:
    # https://learn.microsoft.com/en-us/graph/api/agentidentity-update?view=graph-rest-1.0
    assert (write.method, str(write.url)) == ("PATCH", PATCH_URL)
    assert json.loads(write.content) == {"accountEnabled": False}
    assert write.headers["authorization"] == f"Bearer {TOKEN}"
    assert write.headers["content-type"].startswith("application/json")
    sign_in, = [request for request in graph.requests if request.url.host == "login.microsoftonline.com"]
    assert dict(httpx.QueryParams(sign_in.content.decode("ascii")))["scope"] == "https://graph.microsoft.com/.default"
    assert len(graph.requests) == 2  # the sign-in and the one change; nothing is read or retried
    body = r.json()
    assert body["ok"] is True and body["platform"] == "entra_agent_id" and body["action"] == "off"
    assert "Microsoft Entra Agent ID" in body["message"] and "switched off" in body["message"]


def test_it_can_be_switched_back_on(client, graph, audit_rows):
    _enroll(client)
    r = client.post(SWITCH, json={"action": "on", "confirmed": True})
    assert r.status_code == 200
    write, = graph.writes()
    assert json.loads(write.content) == {"accountEnabled": True}
    assert r.json()["action"] == "on" and "switched back on" in r.json()["message"]


def test_it_is_audited_before_and_after_with_no_content(client, graph, audit_rows):
    _enroll(client)
    _off(client)
    mine = [row for row in audit_rows if row["kind"].startswith("agent_platform_switch")]
    assert [row["kind"] for row in mine] == ["agent_platform_switch_requested", "agent_platform_switched"]
    # the request was on record before anything was sent
    assert "agent_platform_switch_requested" in audit_rows.before_write[0]
    assert "agent_platform_switched" not in audit_rows.before_write[0]
    for row in mine:
        assert row["external_agent"] == AGENT and row["platform"] == "entra_agent_id"
        assert row["action"] == "off" and row["requested_by"]
    assert mine[1]["outcome"] == "switched"
    blob = json.dumps(mine)
    assert IDENTITY not in blob  # the platform's own id is not needed in the trail


def test_the_next_check_and_the_record_are_left_to_the_platform_as_it_is(client, graph, audit_rows):
    """A successful change writes nothing of its own: the next platform check
    sees the identity disabled and reports it the way it reports any change."""
    _enroll(client)
    before = _files()
    assert _off(client).status_code == 200
    assert _files() == before


# ------------------------------------------------------------------ failures

@pytest.mark.parametrize("status, words", [
    (401, "did not accept"), (403, "AgentIdentity.EnableDisable.All"), (404, "does not exist"),
    (429, "limiting requests"), (500, "HTTP 500"),
])
def test_a_platform_refusal_is_shown_in_plain_words_and_changes_nothing_here(
        client, graph, audit_rows, status, words):
    _enroll(client)
    graph.patch = httpx.Response(status, json={"error": {"code": "Forbidden", "message": "secret detail"}})
    before = _files()
    r = _off(client)
    assert r.status_code == 502
    assert words in r.json()["detail"] and "nothing was changed" in r.json()["detail"].lower()
    assert "secret detail" not in r.text and "Forbidden" not in r.text
    assert len(graph.writes()) == 1  # never retried
    assert _files() == before
    mine = [row for row in audit_rows if row["kind"].startswith("agent_platform_switch")]
    assert [row["kind"] for row in mine] == ["agent_platform_switch_requested", "agent_platform_switch_failed"]
    assert mine[1]["outcome"] == "failed" and mine[1]["http_status"] == status
    assert "secret detail" not in json.dumps(mine)


def test_a_platform_that_does_not_answer_in_time_is_a_plain_failure(client, graph, audit_rows):
    _enroll(client)
    graph.patch = httpx.ReadTimeout("slow", request=httpx.Request("PATCH", PATCH_URL))
    r = _off(client)
    assert r.status_code == 502 and "did not answer in time" in r.json()["detail"]
    assert len(graph.writes()) == 1


def test_a_sign_in_that_fails_sends_no_change(client, graph, audit_rows, monkeypatch):
    _enroll(client)
    monkeypatch.delenv("WATCH_SECRET")
    r = _off(client)
    assert r.status_code == 502 and graph.writes() == []
    assert "WATCH_SECRET" not in r.text and SECRET not in r.text
    assert [row["kind"] for row in audit_rows if row["kind"].startswith("agent_platform_switch")] == [
        "agent_platform_switch_requested", "agent_platform_switch_failed"]


def test_a_redirect_is_not_followed(client, graph, audit_rows):
    _enroll(client)
    graph.patch = httpx.Response(307, headers={"location": "https://evil.example/"})
    r = _off(client)
    assert r.status_code == 502 and len(graph.requests) == 2


def test_nothing_is_sent_when_the_audit_log_cannot_take_the_request(client, graph, monkeypatch):
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "record", lambda *a, **k: False)
    _enroll(client)
    r = _off(client)
    assert r.status_code == 503 and "audit log" in r.json()["detail"] and graph.requests == []


def test_a_record_that_cannot_be_read_stops_it_before_anything_is_sent(client, graph, audit_rows):
    _enroll(client)
    xa.registry_path().write_text("{not json", encoding="utf-8")
    r = _off(client)
    assert r.status_code in (409, 503) and graph.requests == []


# ------------------------------------------------------------------- secrets

def test_nothing_secret_appears_anywhere(client, graph, audit_rows, caplog):
    _enroll(client)
    with caplog.at_level(logging.DEBUG):
        ok = _off(client)
        graph.patch = httpx.Response(403, json={"error": {"message": f"token {TOKEN} {SECRET}"}})
        failed = _off(client)
    everything = "\n".join([ok.text, failed.text, json.dumps(audit_rows), caplog.text,
                            client.get(SWITCH).text, *_files().values()])
    for secret in (SECRET, TOKEN, "WATCH_SECRET"):
        assert secret not in everything


# ------------------------------------------------------------- what is offered

def test_the_offer_says_what_is_possible_and_what_the_setting_is(client, graph, tmp_path):
    _enroll(client)
    offered = client.get(SWITCH).json()
    assert offered == {"linked": True, "platform": "entra_agent_id", "platform_name": "Microsoft Entra Agent ID",
                       "supported": True, "allowed": True, "state": "", "reason": ""}
    _configure(tmp_path, "")
    offered = client.get(SWITCH).json()
    assert offered["supported"] is True and offered["allowed"] is False
    assert "allow_switch_off = true" in offered["reason"]


def test_an_agent_with_no_link_is_offered_nothing_but_an_explanation(client):
    _enroll(client, ref=None)
    offered = client.get(SWITCH).json()
    assert offered["linked"] is False and offered["supported"] is False
    assert "not linked to a platform" in offered["reason"]
    assert client.get("/api/v1/external-agents/missing/platform-switch").status_code == 404


def test_the_offer_follows_what_the_last_check_saw(client, graph, tmp_path):
    _enroll(client)
    import time

    from maverick import external_agents  # noqa: F401
    store = {"version": 1, "platforms": {}, "unenrolled": {},
             "agents": {AGENT: {"external_ref": f"entra_agent_id:{IDENTITY}", "state": "disabled",
                                "listed": True, "last_checked_at": time.time()}}}
    watch.store_path().write_text(json.dumps(store), encoding="utf-8")
    assert client.get(SWITCH).json()["state"] == "disabled"
