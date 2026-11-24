# ruff: noqa: F811
"""Pushing a released factory agent to Microsoft Foundry. Every request is answered by a stand-in
(``httpx.MockTransport``); nothing talks to Microsoft."""
from __future__ import annotations

import json
from contextlib import contextmanager

import httpx
import pytest

from tests.new.test_agent_factory import (  # noqa: F401  (fixtures and helpers shared with the factory tests)
    app,
    installation,
    model,
    person,
    released_agent,
    write_config,
)

pytest.importorskip("second_shift_runtime.skills_service", reason="needs the runtime with the skills service")

TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
CLIENT = "00001111-aaaa-2222-bbbb-3333cccc4444"
SECRET = "Zx8~Q.fake-client-secret_4hT9"  # pragma: allowlist secret
TOKEN = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."  # pragma: allowlist secret
         "eyJhdWQiOiJmYWtlIiwiaXNzIjoiZmFrZSJ9.c2lnbmF0dXJlLW5vdC1yZWFs")  # pragma: allowlist secret
ENDPOINT = "https://contoso.services.ai.azure.com/api/projects/support"
PROJECT = "contoso/support"
CONNECTION = ("/subscriptions/0000/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/contoso/projects/support/"
              "connections/skills-key")
SKILLS = "https://skills.contoso.example"
CONFIG = ('[factory.foundry]\nallow_push = true\nproject_endpoint = "' + ENDPOINT + '"\n'
          'tenant_id_env = "PUSH_TENANT"\nclient_id_env = "PUSH_CLIENT"\nclient_secret_env = "PUSH_SECRET"\n')


class Foundry:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.answer: object = httpx.Response(201, json={"name": "policy-helper", "versions": {"latest": {"version": "1"}}})
        self.unexpected: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN})
        if request.method == "POST" and request.url.host == "contoso.services.ai.azure.com":
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        self.unexpected.append(f"{request.method} {request.url}")
        return httpx.Response(404)

    def writes(self):
        return [r for r in self.requests if r.url.host == "contoso.services.ai.azure.com"]


@pytest.fixture
def foundry(monkeypatch):
    from maverick import agent_watch
    from maverick.tools import _ssrf

    service = Foundry()

    @contextmanager
    def client(url, timeout=None):
        with httpx.Client(transport=httpx.MockTransport(service), timeout=timeout) as value:
            yield value

    monkeypatch.setattr(_ssrf, "safe_client", client)
    monkeypatch.setattr(agent_watch, "_TOKENS", {})
    monkeypatch.setenv("PUSH_TENANT", TENANT)
    monkeypatch.setenv("PUSH_CLIENT", CLIENT)
    monkeypatch.setenv("PUSH_SECRET", SECRET)
    yield service
    assert service.unexpected == []
    assert all(r.url.scheme == "https" for r in service.requests)


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit_pkg

    rows: list[dict] = []

    def record(kind, *, agent="system", goal_id=None, **payload):
        rows.append({"kind": str(kind), "agent": agent, **payload})
        return True

    monkeypatch.setattr(audit_pkg, "record", record)
    return rows


def configure(installation, text=CONFIG):
    from maverick import config

    base = (installation / "config.toml").read_text(encoding="utf-8")
    (installation / "config.toml").write_text(base + "\n" + text, encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture
def released(person, model, world, foundry, installation, monkeypatch):
    configure(installation)
    return released_agent(person, model, world, skills=[{"name": "fetch_web_page"}])


@pytest.fixture
def world(app):
    from maverick_dashboard._shared import _world

    return _world()


def body(**over):
    return {"confirm_project": PROJECT, "confirm_agent": "policy-helper", "skills_url": SKILLS, "connection_id": CONNECTION, **over}


def push(client, agent, **over):
    return client.post(f"/api/v1/factory/agents/{agent['id']}/versions/1/push/foundry", json=body(**over))


# --- what is sent -----------------------------------------------------------------------------------------------

def test_it_creates_the_prompt_agent_with_exactly_the_documented_request(person, released, foundry):
    out = push(person("boss"), released)
    assert out.status_code == 200, out.text
    (sent,) = foundry.writes()
    assert (sent.method, str(sent.url)) == ("POST", ENDPOINT + "/agents?api-version=v1")
    assert sent.headers["authorization"] == f"Bearer {TOKEN}" and sent.headers["content-type"] == "application/json"
    token_call = foundry.requests[0]
    assert token_call.url.host == "login.microsoftonline.com" and b"scope=https%3A%2F%2Fai.azure.com%2F.default" in token_call.content
    sent_body = json.loads(sent.content)
    assert sent_body["name"] == "policy-helper" and sent_body["definition"]["kind"] == "prompt"
    assert sent_body["definition"]["model"] == "gpt-test"
    (tool,) = sent_body["definition"]["tools"]
    assert tool["openapi"]["auth"]["security_scheme"]["project_connection_id"] == CONNECTION
    assert tool["openapi"]["spec"]["servers"] == [{"url": SKILLS}]
    # the body is the same one the package holds
    from maverick.factory import export, store

    record = store.get(released["id"])
    assert sent_body == export.foundry_agent_body(record, record["versions"][0], SKILLS, CONNECTION)
    assert SECRET not in sent.content.decode() and out.json()["project"] == PROJECT and out.json()["agent"] == "policy-helper"


def test_adding_a_version_uses_the_versions_route(person, released, foundry):
    out = push(person("boss"), released, mode="new_version")
    assert out.status_code == 200, out.text
    (sent,) = foundry.writes()
    assert str(sent.url) == ENDPOINT + "/agents/policy-helper/versions?api-version=v1"
    assert set(json.loads(sent.content)) == {"description", "definition"}


# --- the link ---------------------------------------------------------------------------------------------------

def test_on_success_the_enrollment_is_linked_in_the_form_the_platform_check_reads(person, released, foundry):
    from maverick import agent_watch, external_agents

    assert push(person("boss"), released).json()["external_ref"] == "foundry:contoso/support/policy-helper"
    stored = external_agents._load_sidecar()["policy-helper"]
    assert stored["external_ref"] == "foundry:contoso/support/policy-helper"
    assert agent_watch._parse_ref(stored["external_ref"]) == ("foundry", "contoso/support/policy-helper")
    assert stored["tool_risks"] == {"fetch_web_page": "low"}  # the ratings from the release are kept
    after = person("alice").get(f"/api/v1/factory/agents/{released['id']}").json()
    assert after["foundry"]["agent"] == "policy-helper" and after["enrollment"]["external_ref"].startswith("foundry:")


def test_a_failed_push_changes_nothing_in_second_shift(person, released, foundry):
    from maverick import external_agents

    foundry.answer = httpx.Response(400, json={"error": {"message": "bad model SECRET-TEXT"}})
    out = push(person("boss"), released)
    assert out.status_code == 502 and "HTTP 400" in out.json()["detail"] and "SECRET-TEXT" not in out.text
    assert "not repeated" in out.json()["detail"]
    assert not external_agents._load_sidecar()["policy-helper"].get("external_ref")
    assert person("alice").get(f"/api/v1/factory/agents/{released['id']}").json()["foundry"] is None


@pytest.mark.parametrize("status,fragment", [(401, "did not accept"), (403, "permission"), (404, "nothing at that address"),
                                             (409, "already exists"), (429, "limiting"), (500, "did not expect")])
def test_each_refusal_is_explained_in_plain_words_and_sent_once(person, released, foundry, status, fragment):
    foundry.answer = httpx.Response(status, json={})
    out = push(person("boss"), released)
    assert out.status_code == 502 and fragment in out.json()["detail"]
    assert len(foundry.writes()) == 1  # never retried


def test_a_network_failure_is_not_retried(person, released, foundry):
    foundry.answer = httpx.ConnectError("down")
    out = push(person("boss"), released)
    assert out.status_code == 502 and len(foundry.writes()) == 1 and "not repeated" in out.json()["detail"]


# --- audited before and after -------------------------------------------------------------------------------------

def test_it_is_audited_before_it_is_sent_and_after_with_no_content(person, released, foundry, audit_rows):
    seen = []
    original = foundry.__call__

    def watching(request):
        if request.url.host == "contoso.services.ai.azure.com":
            seen.append([r["kind"] for r in audit_rows])
        return original(request)

    foundry.__class__.__call__ = lambda self, request: watching(request)
    try:
        assert push(person("boss"), released).status_code == 200
    finally:
        foundry.__class__.__call__ = original.__func__
    assert seen == [["factory_foundry_push_requested"]]
    mine = [r for r in audit_rows if r["kind"].startswith("factory_foundry_push")]
    assert [r["kind"] for r in mine] == ["factory_foundry_push_requested", "factory_foundry_push_made"]
    assert mine[0]["requested_by"] == "user:boss" and mine[0]["project"] == PROJECT and mine[0]["foundry_agent"] == "policy-helper"
    text = json.dumps(audit_rows)
    assert SECRET not in text and TOKEN not in text and CONNECTION not in text and "instructions" not in text


def test_a_failure_is_audited_too(person, released, foundry, audit_rows):
    foundry.answer = httpx.Response(403)
    push(person("boss"), released)
    kinds = [r["kind"] for r in audit_rows if r["kind"].startswith("factory_foundry_push")]
    assert kinds == ["factory_foundry_push_requested", "factory_foundry_push_failed"]


def test_an_audit_log_that_cannot_take_the_request_means_nothing_is_sent(person, released, foundry, monkeypatch):
    import maverick.audit as audit_pkg

    monkeypatch.setattr(audit_pkg, "record", lambda *a, **k: False)
    out = push(person("boss"), released)
    assert out.status_code == 503 and foundry.requests == []


# --- off by default, admin only, confirmation ----------------------------------------------------------------------

def test_it_is_off_unless_the_setting_says_so(person, model, world, foundry, installation):
    agent = released_agent(person, model, world, skills=[{"name": "fetch_web_page"}])
    out = push(person("boss"), agent)
    assert out.status_code == 409 and "allow_push = true" in out.json()["detail"] and foundry.requests == []
    configure(installation, CONFIG.replace("allow_push = true", "allow_push = false"))
    assert push(person("boss"), agent).status_code == 409 and foundry.requests == []


@pytest.mark.parametrize("who", ["alice", "carol", "dave"])
def test_only_an_administrator_may_push(person, released, foundry, who):
    assert push(person(who), released).status_code == 403 and foundry.requests == []


@pytest.mark.parametrize("change", [{"confirm_project": "other/project"}, {"confirm_agent": "something-else"}, {"confirm_project": ""}, {"confirm_agent": ""}])
def test_the_request_must_name_the_project_and_agent_it_was_shown(person, released, foundry, change):
    out = push(person("boss"), released, **change)
    assert out.status_code == 409 and "confirmation" in out.json()["detail"] and foundry.requests == []


@pytest.mark.parametrize("change,status", [({"skills_url": ""}, 422), ({"skills_url": "http://plain.example"}, 422),
                                           ({"connection_id": "skills-key"}, 422), ({"mode": "replace"}, 422)])
def test_the_skills_address_and_connection_are_checked_before_anything_is_sent(person, released, foundry, change, status):
    assert push(person("boss"), released, **change).status_code == status and foundry.requests == []


def test_a_draft_or_retired_version_cannot_be_pushed(person, released, foundry):
    boss = person("boss")
    assert boss.post(f"/api/v1/factory/agents/{released['id']}/retire").status_code == 200
    assert push(boss, released).status_code == 409 and foundry.requests == []


@pytest.mark.parametrize("extra", ['project_endpoint = "https://evil.example.com/api/projects/x"', 'client_secret = "abc"',
                                   'tenant_id_env = "not a name"', 'auth = "password"', 'surprise = 1'])
def test_settings_that_cannot_be_used_stop_the_push_without_repeating_them(person, model, world, foundry, installation, extra):
    key = extra.split("=")[0].strip()
    text = "\n".join(line for line in CONFIG.splitlines() if not line.startswith(key)) + "\n" + extra + "\n"
    configure(installation, text)
    agent = released_agent(person, model, world, skills=[{"name": "fetch_web_page"}])
    out = push(person("boss"), agent)
    assert out.status_code == 409 and foundry.requests == []
    for secret_like in ("abc", "evil.example.com", "not a name"):
        assert secret_like not in out.text


def test_a_managed_identity_signs_in_without_any_secret(person, model, world, foundry, installation, monkeypatch):
    import sys
    import types

    calls = []

    class Credential:
        def __init__(self, client_id=None):
            calls.append(client_id)

        def get_token(self, scope):
            calls.append(scope)
            return types.SimpleNamespace(token=TOKEN)

    identity = types.ModuleType("azure.identity")
    identity.ManagedIdentityCredential = Credential
    monkeypatch.setitem(sys.modules, "azure", types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    configure(installation, f'[factory.foundry]\nallow_push = true\nproject_endpoint = "{ENDPOINT}"\nauth = "managed_identity"\n')
    agent = released_agent(person, model, world, skills=[{"name": "fetch_web_page"}])
    assert push(person("boss"), agent).status_code == 200
    assert calls == [None, "https://ai.azure.com/.default"]
    assert [r.url.host for r in foundry.requests] == ["contoso.services.ai.azure.com"]  # no client-credentials sign-in
    assert foundry.requests[0].headers["authorization"] == f"Bearer {TOKEN}"


def test_the_status_says_whether_push_is_on_without_showing_a_credential(person, released):
    out = person("alice").get("/api/v1/factory/status").json()["foundry_push"]
    assert out == {"allowed": True, "ready": True, "project": PROJECT, "problems": []}
