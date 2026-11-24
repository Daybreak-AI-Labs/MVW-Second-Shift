"""Copilot Studio external threat detection: the two calls Copilot Studio makes,
the token check, the decisions, approvals in a chat, and what is kept."""
from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

TENANT = "11111111-2222-3333-4444-555555555555"
APP_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AUDIENCE = "https://second-shift.contoso.test"
ENV_ID = "0c6b1c52-8a6e-4f0e-9a43-6a8f2b1d9c11"
HOST = "contoso.crm.dynamics.com"
BOT_ID = "9f1e3a52-0b7c-4d3a-8c55-1a2b3c4d5e6f"
V2_ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
V1_ISSUER = f"https://sts.windows.net/{TENANT}/"
KID = "test-key-1"

PROMPT_MARK = "PROMPTMARK-send-the-quarterly-payroll"
CHAT_MARK = "CHATMARK-the-customer-is-john-doe"
OUTPUT_MARK = "OUTPUTMARK-customer-at-foobar"
VALUE_MARK = "VALUEMARK-hacker-at-evil"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks() -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_KEY.public_key()))
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}


def _claims(**override) -> dict:
    now = int(time.time())
    claims = {"iss": V2_ISSUER, "aud": AUDIENCE, "exp": now + 600, "iat": now, "nbf": now,
              "sub": "service-principal", "tid": TENANT, "azp": APP_ID, "ver": "2.0"}
    claims.update(override)
    return {k: v for k, v in claims.items() if v is not None}


def _token(key=None, headers=None, **override) -> str:
    return jwt.encode(_claims(**override), key or _KEY, algorithm="RS256",
                      headers={"kid": KID, **(headers or {})})


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _request_body(tool="Send email", inputs=None, agent=BOT_ID, env=ENV_ID) -> dict:
    """The example request from the developer contract, with our ids."""
    return {
        "plannerContext": {
            "userMessage": f"Send an email to the customer {PROMPT_MARK}",
            "thought": "User wants to notify customer",
            "chatHistory": [
                {"id": "m1", "role": "user", "content": CHAT_MARK, "timestamp": "2025-05-25T08:00:00Z"},
                {"id": "m2", "role": "assistant", "content": "Which customer should I email?"},
            ],
            "previousToolOutputs": [{
                "toolId": "tool-123", "toolName": "Get customer email by name",
                "outputs": {"name": "email", "description": "Customer's email address",
                            "type": {"$kind": "String"}, "value": OUTPUT_MARK},
                "timestamp": "2025-05-25T08:00:02Z"}]},
        "toolDefinition": {
            "id": "tool-123", "type": "PrebuiltToolDefinition", "name": tool,
            "description": "Sends an email to specified recipients.",
            "inputParameters": [{"name": "to", "description": "Receiver of the email",
                                 "type": {"$kind": "String"}},
                                {"name": "bcc", "description": "BCC of the email",
                                 "type": {"$kind": "String"}}],
            "outputParameters": [{"name": "result", "description": "Result", "type": {"$kind": "String"}}]},
        "inputValues": inputs if inputs is not None else {"to": "customer@foobar.com", "bcc": VALUE_MARK},
        "conversationMetadata": {
            "agent": {"id": agent, "tenantId": TENANT, "environmentId": env, "isPublished": True},
            "user": {"id": "user-guid-0001", "tenantId": TENANT},
            "trigger": {"id": "trigger-guid", "schemaName": "trigger-schema"},
            "conversationId": "conv-id", "planId": "plan-guid", "planStepId": "step-1"},
    }


CONFIG = f"""
[external_agents]
enable = true
show_request_detail = false

[copilot_studio_gate]
enable = true
tenant_id = "{TENANT}"
app_id = "{APP_ID}"
audience = "{AUDIENCE}"
unenrolled = "allow"
on_error = "block"
default_risk = "medium"

[copilot_studio_gate.environments]
"{ENV_ID}" = "{HOST}"
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config, killswitch, world_model
    from maverick._oidc_jwks import _resolvers
    from maverick.audit import writer as audit_writer

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    check = killswitch.check
    monkeypatch.setattr(killswitch, "check", lambda **options: check(**{**options, "force_refresh": True}))
    killswitch.clear()
    _resolvers.clear()
    (tmp_path / "config.toml").write_text(CONFIG, encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    killswitch.clear()
    _resolvers.clear()
    config.reset_config_cache()


@pytest.fixture
def keys_fetched(monkeypatch):
    """The tenant's published signing keys, served from a mock instead of Microsoft."""
    urls: list[str] = []

    def fetch(self):
        urls.append(self.uri)
        return _jwks()

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch)
    return urls


@pytest.fixture
def client(home, keys_fetched):
    from maverick_dashboard.app import app

    # Microsoft's calls carry no Origin header and no dashboard sign-in.
    with TestClient(app, base_url="https://second-shift.contoso.test") as c:
        yield c


def _seen(client) -> list[dict]:
    """The administrator's view: agents that asked while not enrolled."""
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as admin:
        reply = admin.get("/api/v1/copilot-studio-gate")
    assert reply.status_code == 200, reply.text
    return reply.json()["not_enrolled"]


def _rewrite_config(home, text: str) -> None:
    from maverick import config

    (home / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _enroll(tools=("Send email:low",), **kw):
    from maverick import external_agents as xa

    args = {"description": "support agent", "owner": "ops@contoso.test", "department": "support",
            "max_risk": "high", "enrolled_by": "admin@contoso.test", "allow_tools": list(tools),
            "external_ref": f"copilot_studio:{HOST}/{BOT_ID}"}
    args.update(kw)
    return xa.enroll("support-bot", "copilot", **args)


def _auth(token=None, **override) -> dict:
    return {"Authorization": f"Bearer {token or _token(**override)}"}


def _analyze(client, body=None, headers=None, version="2025-05-01"):
    return client.post(f"/copilot-studio/analyze-tool-execution?api-version={version}",
                       json=body if body is not None else _request_body(),
                       headers=headers if headers is not None else _auth())


def _approve(approval_id: int) -> None:
    from maverick.world_model import WorldModel

    world = WorldModel()
    event = world.decide_approval_audited(approval_id, "approved", decided_by="user:dana@contoso.test")
    assert event is not None
    world.mark_approval_audit_delivered(event.event_id)
    assert world.get_approval(approval_id).status == "approved"


# ---------------------------------------------------------------- token check


def test_a_good_token_is_accepted_and_the_keys_come_from_the_tenants_published_address(client, keys_fetched):
    reply = client.post("/copilot-studio/validate?api-version=2025-05-01", headers=_auth())
    assert reply.status_code == 200, reply.text
    assert reply.json() == {"isSuccessful": True, "status": "OK"}
    assert keys_fetched == [f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"]


def test_a_version_1_token_from_the_same_app_is_accepted(client):
    token = _token(iss=V1_ISSUER, azp=None, appid=APP_ID, ver="1.0")
    assert client.post("/copilot-studio/validate", headers=_auth(token)).status_code == 200


def test_the_services_own_application_id_is_an_accepted_audience_only_when_set(home, client):
    own = "bbbbbbbb-1111-2222-3333-444444444444"
    assert client.post("/copilot-studio/validate", headers=_auth(aud=own)).status_code == 401
    _rewrite_config(home, CONFIG.replace(f'audience = "{AUDIENCE}"', f'audience = "{AUDIENCE}"\napi_client_id = "{own}"'))
    assert client.post("/copilot-studio/validate", headers=_auth(aud=own)).status_code == 200


def _forged_alg_none() -> str:
    return f"{_b64({'alg': 'none', 'typ': 'JWT', 'kid': KID})}.{_b64(_claims())}."


def _forged_hs256() -> str:
    return jwt.encode(_claims(), "x" * 64, algorithm="HS256", headers={"kid": KID})


_NOW = int(time.time())
BAD_TOKENS = {
    "wrong audience": lambda: _token(aud="https://someone-else.test"),
    "wrong issuer": lambda: _token(iss="https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"),
    "other issuer form": lambda: _token(iss=f"https://evil.test/{TENANT}/v2.0"),
    "wrong application": lambda: _token(azp="cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee"),
    "no application claim": lambda: _token(azp=None),
    "wrong tenant claim": lambda: _token(tid="99999999-2222-3333-4444-555555555555"),
    "expired": lambda: _token(exp=_NOW - 60, iat=_NOW - 700, nbf=_NOW - 700),
    "not yet valid": lambda: _token(nbf=_NOW + 3600),
    "no expiry": lambda: _token(exp=None),
    "signed by another key": lambda: _token(key=_OTHER_KEY),
    "signed with an unknown key id": lambda: _token(headers={"kid": "unknown-kid"}),
    "a signed-in user's token": lambda: _token(scp="access_as_user"),
    "alg none": _forged_alg_none,
    "hmac with the same key id": _forged_hs256,
    "not a token": lambda: "abc.def",
}


@pytest.mark.parametrize("name", sorted(BAD_TOKENS))
def test_a_token_that_is_not_right_gets_401_and_the_documented_error_body(client, name):
    for path in ("validate", "analyze-tool-execution"):
        reply = client.post(f"/copilot-studio/{path}?api-version=2025-05-01",
                            json=_request_body(), headers={"Authorization": f"Bearer {BAD_TOKENS[name]()}"})
        assert reply.status_code == 401, (name, reply.text)
        body = reply.json()
        assert set(body) == {"errorCode", "message", "httpStatus"} and body["httpStatus"] == 401
        assert isinstance(body["errorCode"], int)


def test_a_missing_or_wrong_kind_of_authorization_gets_401(client):
    for headers in ({}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"}):
        reply = client.post("/copilot-studio/analyze-tool-execution", json=_request_body(), headers=headers)
        assert reply.status_code == 401 and reply.json()["httpStatus"] == 401


def test_nothing_is_accepted_until_the_tenant_application_and_address_are_set(home, client):
    _rewrite_config(home, CONFIG.replace(f'app_id = "{APP_ID}"', ""))
    assert client.post("/copilot-studio/validate", headers=_auth()).status_code == 401


def test_signing_keys_that_cannot_be_fetched_give_503_not_a_decision(home, client, monkeypatch):
    def broken(self):
        raise OSError("unreachable")

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", broken)
    reply = _analyze(client)
    assert reply.status_code == 503 and reply.json()["httpStatus"] == 503


# ------------------------------------------------------------------ validate


def test_validate_is_ready_only_when_second_shift_can_decide(home, client):
    assert client.post("/copilot-studio/validate", headers=_auth()).json() == {
        "isSuccessful": True, "status": "OK"}
    _rewrite_config(home, CONFIG.replace("enable = true\ntenant_id", "enable = false\ntenant_id"))
    off = client.post("/copilot-studio/validate", headers=_auth())
    assert off.status_code == 503 and off.json()["httpStatus"] == 503 and "turned off" in off.json()["message"]
    _rewrite_config(home, CONFIG.replace("[external_agents]\nenable = true", "[external_agents]\nenable = false"))
    assert client.post("/copilot-studio/validate", headers=_auth()).status_code == 503
    _rewrite_config(home, CONFIG.replace('on_error = "block"', 'on_error = "maybe"'))
    assert client.post("/copilot-studio/validate", headers=_auth()).status_code == 503


def test_validate_fails_when_a_settings_file_cannot_be_read(home, client):
    (home / "dashboard-config.toml").write_text("this is [not toml", encoding="utf-8")
    from maverick import config

    config.reset_config_cache()
    config.load_config()
    assert config.config_source_errors()
    assert client.post("/copilot-studio/validate", headers=_auth()).status_code == 503


# ------------------------------------------------------------------- decisions


def test_the_documented_example_request_is_allowed_for_an_enrolled_agent(client):
    _enroll(tools=("Send email:low",))
    reply = _analyze(client)
    assert reply.status_code == 200 and reply.json() == {"blockAction": False}


def test_the_documented_example_request_is_blocked_with_a_plain_reason(client):
    _enroll(tools=("Get customer email by name:low",))  # "Send email" is not on its list
    body = _analyze(client).json()
    assert body["blockAction"] is True
    assert body["reason"].startswith("Second Shift blocked this action: ")
    assert isinstance(body["reasonCode"], int)


def test_unknown_fields_and_a_newer_api_version_are_tolerated(client):
    _enroll()
    body = _request_body()
    body["somethingNew"] = {"deep": [1, 2, 3]}
    body["toolDefinition"]["futureField"] = True
    body["conversationMetadata"]["agent"]["version"] = "7"
    reply = _analyze(client, body, version="2031-01-01")
    assert reply.status_code == 200 and reply.json() == {"blockAction": False}
    assert client.post("/copilot-studio/validate", headers=_auth()).status_code == 200


def test_a_request_without_what_is_needed_gets_400_in_the_documented_body(client):
    for body in ({}, {"toolDefinition": {"name": "x"}}, [1, 2],
                 {**_request_body(), "inputValues": "text"},
                 {**_request_body(), "toolDefinition": {"id": "t"}}):
        reply = _analyze(client, body)
        assert reply.status_code == 400
        assert set(reply.json()) == {"errorCode", "message", "httpStatus"}
    raw = client.post("/copilot-studio/analyze-tool-execution", content=b"{not json", headers=_auth())
    assert raw.status_code == 400


def test_a_body_that_is_too_large_is_refused(client):
    reply = client.post("/copilot-studio/analyze-tool-execution", headers=_auth(),
                        content=b'{"x": "' + b"a" * (1024 * 1024 + 10) + b'"}')
    assert reply.status_code == 413 and reply.json()["httpStatus"] == 413


def test_an_agent_that_is_not_enrolled_is_allowed_and_recorded_as_seen_by_default(client):
    reply = _analyze(client)
    assert reply.json() == {"blockAction": False}
    seen = _seen(client)
    assert [(r["environment_id"], r["agent_id"], r["tool"]) for r in seen] == [(ENV_ID, BOT_ID, "Send email")]
    assert seen[0]["reference"] == f"copilot_studio:{HOST}/{BOT_ID}"


def test_an_agent_that_is_not_enrolled_is_blocked_when_the_settings_say_so(home, client):
    _rewrite_config(home, CONFIG.replace('unenrolled = "allow"', 'unenrolled = "block"'))
    body = _analyze(client).json()
    assert body["blockAction"] is True and "not enrolled" in body["reason"]


def test_an_environment_that_is_not_in_the_settings_follows_the_unenrolled_setting(home, client):
    other = _request_body(env="00000000-0000-0000-0000-000000000001")
    assert _analyze(client, other).json() == {"blockAction": False}
    _rewrite_config(home, CONFIG.replace('unenrolled = "allow"', 'unenrolled = "block"'))
    assert _analyze(client, other).json()["blockAction"] is True


def test_the_agent_is_found_whatever_the_capitals_in_the_ids(client):
    _enroll(external_ref=f"copilot_studio:{HOST.upper()}/{BOT_ID.upper()}")
    body = _request_body(agent=BOT_ID.upper(), env=ENV_ID.upper())
    assert _analyze(client, body).json() == {"blockAction": False}
    assert _seen(client) == []


def test_the_risk_comes_from_the_enrollment_rating_else_the_setting(home, client):
    # Rated high at enrollment: waits for a person. Unrated: takes default_risk (medium here).
    _enroll(tools=("Send email:high", "Lookup"))
    assert _analyze(client).json()["blockAction"] is True
    assert _analyze(client, _request_body(tool="Lookup")).json() == {"blockAction": False}
    _rewrite_config(home, CONFIG.replace('default_risk = "medium"', 'default_risk = "high"'))
    waiting = _analyze(client, _request_body(tool="Lookup")).json()
    assert waiting["blockAction"] is True and "needs approval" in waiting["reason"]


# -------------------------------------------------------------------- approval


def _request_number(body: dict) -> int:
    import re

    match = re.search(r"request #(\d+)", body["reason"])
    assert match, body
    return int(match.group(1))


def test_an_action_that_needs_approval_is_blocked_then_allowed_once_after_a_person_approves(client):
    _enroll(tools=("Send email:high",))
    first = _analyze(client).json()
    assert first["blockAction"] is True
    number = _request_number(first)
    assert first["reason"] == (f"This action needs approval in Second Shift (request #{number}). "
                               "Ask again once it has been approved.")
    # Asking again before anyone decides does not pile up more requests.
    assert _request_number(_analyze(client).json()) == number
    from maverick.world_model import WorldModel
    assert len(WorldModel().pending_approvals()) == 1

    _approve(number)
    assert _analyze(client).json() == {"blockAction": False}
    # A used approval cannot be reused: the next ask is a new request.
    again = _analyze(client).json()
    assert again["blockAction"] is True and _request_number(again) != number


def test_different_inputs_need_their_own_approval(client):
    _enroll(tools=("Send email:high",))
    number = _request_number(_analyze(client).json())
    _approve(number)
    other = _request_body(inputs={"to": "someone@else.test", "bcc": ""})
    changed = _analyze(client, other).json()
    assert changed["blockAction"] is True and _request_number(changed) != number
    # The approved one is still waiting to be used once, by the same inputs.
    assert _analyze(client).json() == {"blockAction": False}


def test_an_approval_belongs_to_one_agent_and_one_tool(home, client):
    _enroll(tools=("Send email:high", "Other tool:high"))
    number = _request_number(_analyze(client).json())
    _approve(number)
    assert _analyze(client, _request_body(tool="Other tool")).json()["blockAction"] is True
    assert _analyze(client).json() == {"blockAction": False}


def test_an_approval_that_waited_too_long_is_not_used(home, client, monkeypatch):
    _enroll(tools=("Send email:high",))
    number = _request_number(_analyze(client).json())
    _approve(number)
    import types

    from maverick import copilot_studio_gate as gate

    real = time.time
    monkeypatch.setattr(gate, "time", types.SimpleNamespace(time=lambda: real() + 1000, monotonic=time.monotonic))
    late = _analyze(client).json()
    assert late["blockAction"] is True and _request_number(late) != number


def test_a_declined_request_is_not_allowed(client):
    _enroll(tools=("Send email:high",))
    number = _request_number(_analyze(client).json())
    from maverick.world_model import WorldModel
    world = WorldModel()
    event = world.decide_approval_audited(number, "denied", decided_by="user:dana@contoso.test")
    world.mark_approval_audit_delivered(event.event_id)
    body = _analyze(client).json()
    assert body["blockAction"] is True and "declined" in body["reason"] and f"#{number}" in body["reason"]


def test_a_contained_agent_is_blocked_even_with_an_approval(client):
    from maverick import external_agents as xa

    _enroll(tools=("Send email:high",))
    number = _request_number(_analyze(client).json())
    _approve(number)
    xa.contain("support-bot", contained_by="admin@contoso.test")
    body = _analyze(client).json()
    assert body["blockAction"] is True and "paused" in body["reason"]
    xa.release("support-bot", released_by="admin@contoso.test")
    assert _analyze(client).json() == {"blockAction": False}  # the approval was not spent


def test_a_contained_agent_is_blocked(client):
    from maverick import external_agents as xa

    _enroll()
    xa.contain("support-bot", contained_by="admin@contoso.test")
    body = _analyze(client).json()
    assert body["blockAction"] is True and body["reason"].startswith("Second Shift blocked this action: ")


def test_the_emergency_stop_blocks_even_an_approved_action(client):
    from maverick import killswitch

    _enroll(tools=("Send email:high",))
    number = _request_number(_analyze(client).json())
    _approve(number)
    killswitch.halt("incident")
    body = _analyze(client).json()
    assert body["blockAction"] is True and "emergency stop" in body["reason"]
    killswitch.clear()
    assert _analyze(client).json() == {"blockAction": False}


# ---------------------------------------------------------------- when it cannot decide


def test_the_gate_turned_off_follows_on_error(home, client):
    _enroll()
    off = CONFIG.replace("enable = true\ntenant_id", "enable = false\ntenant_id")
    _rewrite_config(home, off)
    assert _analyze(client).json()["blockAction"] is True
    _rewrite_config(home, off.replace('on_error = "block"', 'on_error = "allow"'))
    assert _analyze(client).json() == {"blockAction": False}


def test_unreadable_settings_follow_on_error_and_default_to_block(home, client):
    from maverick import config

    _enroll()
    (home / "dashboard-config.toml").write_text("this is [not toml", encoding="utf-8")
    config.reset_config_cache()
    config.load_config()
    assert config.config_source_errors()
    assert _analyze(client).json()["blockAction"] is True
    _rewrite_config(home, CONFIG.replace('on_error = "block"', 'on_error = "allow"'))
    (home / "dashboard-config.toml").write_text("this is [not toml", encoding="utf-8")
    config.reset_config_cache()
    assert _analyze(client).json() == {"blockAction": False}


def test_an_unusable_on_error_value_means_block(home, client):
    _rewrite_config(home, CONFIG.replace('on_error = "block"', 'on_error = "shrug"'))
    assert _analyze(client).json()["blockAction"] is True


def test_a_failure_while_deciding_follows_on_error(home, client, monkeypatch):
    from maverick import external_agents as xa

    _enroll()
    monkeypatch.setattr(xa, "screen", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(PROMPT_MARK)))
    assert _analyze(client).json()["blockAction"] is True
    _rewrite_config(home, CONFIG.replace('on_error = "block"', 'on_error = "allow"'))
    assert _analyze(client).json() == {"blockAction": False}


def test_a_decision_that_runs_past_the_time_limit_follows_on_error(home, client, monkeypatch):
    from maverick import copilot_studio_gate as gate
    from maverick_dashboard import copilot_studio_gate_api as api

    _enroll()
    monkeypatch.setattr(api, "_DEADLINE_SECONDS", 0.3)
    monkeypatch.setattr(gate, "decide", lambda *a, **k: time.sleep(1.0))
    started = time.monotonic()
    body = _analyze(client).json()
    assert body["blockAction"] is True and time.monotonic() - started < 0.9


# ----------------------------------------------------------------------- privacy


def _everything_kept(home: Path) -> str:
    """Every byte kept under the data folder: audit entries, saved records, the world database."""
    chunks = []
    for path in sorted(home.rglob("*")):
        if path.is_file():
            chunks.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(chunks)


MARKS = (PROMPT_MARK, CHAT_MARK, OUTPUT_MARK, VALUE_MARK, "customer@foobar.com")


def test_nothing_from_the_conversation_is_logged_audited_saved_or_returned(home, client, caplog):
    caplog.set_level(logging.DEBUG)
    _enroll(tools=("Send email:high",))
    replies = [_analyze(client).text]                      # waits for approval
    _approve(_request_number(json.loads(replies[0])))
    replies.append(_analyze(client).text)                  # allowed once
    replies.append(_analyze(client, _request_body(agent="aaaaaaaa-0000-0000-0000-000000000000")).text)  # not enrolled
    replies.append(_analyze(client, _request_body(tool="Unlisted tool")).text)                # refused
    replies.append(_analyze(client, {**_request_body(), "inputValues": "oops"}).text)         # bad request
    replies.append(json.dumps(_seen(client)))
    for mark in MARKS:
        assert all(mark not in reply for reply in replies), mark
        assert mark not in caplog.text, mark
        assert mark not in _everything_kept(home), mark
    # What is kept is what the contract of this service says it keeps.
    kept = _everything_kept(home)
    assert "Send email" in kept and BOT_ID in kept and ENV_ID in kept
    assert "user-guid-0001" not in kept


def test_the_approver_sees_a_short_redacted_summary_only_when_request_detail_is_on(home, client):
    from maverick.world_model import WorldModel

    _rewrite_config(home, CONFIG.replace("show_request_detail = false", "show_request_detail = true"))
    _enroll(tools=("Send email:high",))
    secret = "sk-ant-api03-" + "A" * 40  # pragma: allowlist secret
    inputs = {"to": "customer@foobar.com", "note": f"use key {secret}"}
    number = _request_number(_analyze(client, _request_body(inputs=inputs)).json())
    card = WorldModel().get_approval(number).detail
    assert "Send email" in card and "customer@foobar.com" in card
    assert secret not in card and secret not in _everything_kept(home)
    for mark in (PROMPT_MARK, CHAT_MARK, OUTPUT_MARK):
        assert mark not in card and mark not in _everything_kept(home)


def test_the_user_id_is_kept_only_when_record_user_is_on(home, client):
    _enroll()
    _analyze(client)
    assert "user-guid-0001" not in _everything_kept(home)
    _rewrite_config(home, CONFIG.replace('default_risk = "medium"', 'default_risk = "medium"\nrecord_user = true'))
    _analyze(client, _request_body(agent="aaaaaaaa-0000-0000-0000-000000000000"))
    assert "user-guid-0001" in _everything_kept(home)


# ------------------------------------------------------------------------ timing


def test_a_decision_is_well_under_one_second_with_the_audit_log_on(home, client):
    _enroll(tools=("Send email:low",))
    _analyze(client)  # the first call fetches the signing keys; later ones use them
    times = []
    for index in range(40):
        body = _request_body(inputs={"to": f"person{index}@foobar.com"},
                             agent=BOT_ID if index % 2 else "aaaaaaaa-0000-0000-0000-000000000000")
        started = time.perf_counter()
        reply = _analyze(client, body)
        times.append(time.perf_counter() - started)
        assert reply.status_code == 200
    times.sort()
    p95 = times[int(len(times) * 0.95) - 1]
    print(f"decision time over {len(times)} calls: median {times[len(times) // 2] * 1000:.0f} ms, "
          f"p95 {p95 * 1000:.0f} ms, max {times[-1] * 1000:.0f} ms")
    assert p95 < 0.4 and times[-1] < 0.9
    from maverick.audit import default_audit_log
    assert default_audit_log().tail(5), "the audit log was off, so this timed nothing"


def test_the_routes_are_not_behind_the_browser_sign_in(home, keys_fetched, monkeypatch):
    """With a dashboard token set, Microsoft's call still needs only its own token."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-secret-value")  # pragma: allowlist secret
    from maverick_dashboard.app import app

    with TestClient(app, base_url="https://second-shift.contoso.test") as c:
        assert c.post("/copilot-studio/validate", headers=_auth()).status_code == 200
        assert c.get("/api/v1/copilot-studio-gate").status_code in (401, 403)  # the list is not


def test_the_settings_example_in_the_docs_is_what_the_code_reads():
    from maverick import copilot_studio_gate as gate

    text = (Path(__file__).resolve().parents[2] / "docs" / "copilot-studio-gate.md").read_text(encoding="utf-8")
    for key in ("enable", "tenant_id", "app_id", "audience", "api_client_id", "unenrolled", "on_error",
                "default_risk", "approval_window_seconds", "record_user", "environments"):
        assert key in text
    assert gate.SECTION in text


def test_a_decision_the_audit_log_refuses_to_record_is_blocked_whatever_on_error_says(home, client, monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit import AuditRefused

    _rewrite_config(home, CONFIG.replace('on_error = "block"', 'on_error = "allow"'))
    monkeypatch.setattr(audit_pkg, "record", lambda *a, **k: (_ for _ in ()).throw(AuditRefused("sealed")))
    body = _analyze(client).json()  # not enrolled: the gate writes its own audit entry
    assert body["blockAction"] is True and "record" in body["reason"]


def test_with_postgres_the_agents_seen_are_kept_there(home, client, records_in_postgres):
    from maverick import copilot_studio_gate as gate
    from tests.new.conftest import saved_records

    assert _analyze(client).json() == {"blockAction": False}
    assert [(r["agent_id"], r["tool"]) for r in gate.seen_unenrolled()] == [(BOT_ID, "Send email")]
    assert not gate.store_path().exists()
    assert "copilot_studio_gate.json" in saved_records(records_in_postgres)


def test_with_postgres_a_damaged_record_is_refused(home, client, records_in_postgres):
    from maverick import copilot_studio_gate as gate
    from maverick import record_documents
    from tests.new.conftest import saved_records

    record_documents.at(gate.store_path()).write_text("[1, 2]")
    with pytest.raises(RuntimeError, match="cannot be read"):
        gate.seen_unenrolled()
    assert saved_records(records_in_postgres)["copilot_studio_gate.json"] == "[1, 2]"
