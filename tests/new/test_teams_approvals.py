"""Approve in Microsoft Teams, proven without a Teams tenant.

Requests are signed with a locally generated key whose public half is served as
the Bot Connector's key document, every outbound call goes through a recording
stand-in, and decisions run through the real approval rules, the real world
model and the real role list. Nothing here reaches Microsoft."""
from __future__ import annotations

import json
import logging
import time

import pytest

jwt = pytest.importorskip("jwt", reason="verifying Teams requests needs PyJWT")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

APP_ID = "0f0f0f0f-1111-2222-3333-444444444444"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER_TENANT = "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"
SECRET = "client-secret-value-9X7"  # pragma: allowlist secret
SERVICE_URL = "https://smba.trafficmanager.net/emea/"
ISSUER = "https://api.botframework.com"
AAD = {"alice": "11111111-aaaa-aaaa-aaaa-111111111111", "bob": "22222222-bbbb-bbbb-bbbb-222222222222",
       "carol": "33333333-cccc-cccc-cccc-333333333333", "dave": "44444444-dddd-dddd-dddd-444444444444"}
ROLES = {"user:alice": "approver", "user:bob": "approver", "user:carol": "viewer", "user:dave": "operator"}


# ---------------------------------------------------------------- stand-ins


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key, kid="k1", endorsements=("msteams",)) -> dict:
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public.update({"kid": kid, "use": "sig", "alg": "RS256", "endorsements": list(endorsements)})
    return {"keys": [public]}


def _pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _token(key, *, aud=APP_ID, iss=ISSUER, exp_delta=3600, kid="k1", alg="RS256",
           serviceurl=SERVICE_URL) -> str:
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "exp": now + exp_delta, "iat": now, "nbf": now - 10,
              "serviceurl": serviceurl}
    secret = "x" * 40 if alg.startswith("HS") else _pem(key)
    return jwt.encode(claims, secret, algorithm=alg, headers={"kid": kid})


class FakeTransport:
    """Records every outbound call; answers from ``responses`` or with a default."""

    def __init__(self):
        self.calls: list[dict] = []
        self.responses: dict = {}
        self.counter = 0

    def __call__(self, method, url, *, headers=None, json_body=None, data=None, timeout=15.0):
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "json": json_body,
                           "data": data})
        if "/oauth2/v2.0/token" in url:
            return self.responses.get("token", (200, {"access_token": "bot-token-1", "expires_in": 3600}))
        for fragment, answer in self.responses.items():
            if fragment != "token" and fragment in f"{method} {url}":
                return answer
        if method == "GET":
            return 200, {}
        self.counter += 1
        if method == "POST" and url.endswith("/v3/conversations"):
            return 201, {"id": f"conv-{self.counter}", "activityId": f"act-{self.counter}"}
        return 201, {"id": f"act-{self.counter}"}

    def sent(self, method="POST", containing="/activities"):
        return [c for c in self.calls if c["method"] == method and containing in c["url"]
                and "oauth2" not in c["url"]]


# ------------------------------------------------------------------ fixtures


@pytest.fixture
def env(tmp_path, monkeypatch, rsa_key):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("TEAMS_BOT_SECRET", SECRET)
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")

    class Env:
        path = tmp_path

        def configure(self, extra: str = "", enabled: bool = True, tenant: str = TENANT) -> None:
            (tmp_path / "config.toml").write_text(
                f'[teams]\nenabled = {str(enabled).lower()}\napp_id = "{APP_ID}"\n'
                f'tenant_id = "{tenant}"\n{extra}\n', encoding="utf-8")
            config.reset_config_cache()

        def roster(self, roles: dict | None = None) -> None:
            path = tmp_path / "dashboard-users.json"
            path.write_text(json.dumps(ROLES if roles is None else roles), encoding="utf-8")
            path.chmod(0o600)

    e = Env()
    e.configure()
    e.roster()
    return e


@pytest.fixture
def world(env):
    from maverick_dashboard._shared import _world

    return _world()


@pytest.fixture
def transport():
    return FakeTransport()


@pytest.fixture
def bot(env, world, transport, rsa_key, monkeypatch):
    from maverick_dashboard import teams_bot

    built = teams_bot.build_bot(transport=transport, keys=teams_bot.SigningKeys(jwks=_jwks(rsa_key)),
                                world=world)
    # The card updates the world model asks for build their own bot: give them this one.
    monkeypatch.setattr(teams_bot, "build_bot", lambda **kw: built)
    return built


_BACKGROUND = {"post": False}


@pytest.fixture(autouse=True)
def inline_background(monkeypatch):
    """Run the card updates the world model asks for right away, so a test can
    look. Posting a new card on creation runs only in the test that asks for it."""
    from maverick import approval_notify

    _BACKGROUND["post"] = False

    def spawn(function, action, *args):
        if action != "post_approval" or _BACKGROUND["post"]:
            function(action, *args)

    monkeypatch.setattr(approval_notify, "_spawn", spawn)


def _park(world, *, risk="medium", requested_by="agent:helpdesk", agent_says="Please send the contract",
          provenance="external_agents", expires_in=900):
    """Park an outside agent's action the way screening does; returns (id, binding)."""
    from maverick.approval_cards import (
        build_approval_card,
        decode_approval_detail,
        encode_approval_detail,
    )

    action = "external:helpdesk:send_contract"
    card = build_approval_card(
        action=action, summary="Review external agent action send_contract",
        target_label="External agent helpdesk: send_contract",
        target={"agent_id": "helpdesk", "tool": "send_contract"},
        parameters={"detail": agent_says, "risk": risk},
        parameter_summary=[f"Resolved risk: {risk}", f"The agent says: {agent_says}"],
        actor=requested_by, workspace="local", role="external_agent_operator",
        authority_versions={"request_schema": "second-shift.operation-approval.v1"},
        input_versions={"request_sha256": "b" * 64}, credential_versions={"session_sha256": "a" * 64},
        budget={"state": "governed_again_at_execution"}, expires_at=time.time() + expires_in,
        known_effects=["Records a human decision for this exact screened action."],
        unresolved_assumptions=["This approval does not run the action."],
        before="The action stays blocked.", after="The decision is available to the agent.",
        irreversible=False)
    detail = encode_approval_detail(card)
    approval_id = world.create_approval(action, risk=risk, scope="finance", detail=detail,
                                        provenance=provenance, approvals_required=1,
                                        requested_by=requested_by)
    return approval_id, decode_approval_detail(detail)["binding_sha256"]


def _invoke(verb, approval_id, binding, *, who="alice", activity_id="inv-1", tenant=TENANT, **data):
    return {
        "type": "invoke", "name": "adaptiveCard/action", "id": activity_id, "channelId": "msteams",
        "serviceUrl": SERVICE_URL, "replyToId": "card-1",
        "from": {"id": f"29:{who}", "aadObjectId": AAD[who], "name": who.title()},
        "conversation": {"id": f"19:{who}", "conversationType": "personal", "tenantId": tenant},
        "recipient": {"id": f"28:{APP_ID}"}, "channelData": {"tenant": {"id": tenant}},
        "value": {"action": {"type": "Action.Execute", "verb": verb,
                             "data": {"approval_id": approval_id, "binding": binding, **data}},
                  "trigger": "manual"},
    }


CLAIMS = {"serviceurl": SERVICE_URL}


def _link(who, principal=None):
    from maverick import teams_identity

    teams_identity.link(AAD[who], principal or f"user:{who}", actor="admin")


def _message_text(answer: dict) -> str:
    return json.dumps(answer["value"]) if answer["type"] == "application/vnd.microsoft.card.adaptive" \
        else str(answer["value"])


def _status(world, approval_id):
    return world.get_approval(approval_id).status


# --------------------------------------------- Bot Connector authentication


def test_a_correctly_signed_request_verifies(rsa_key, bot):
    claims = bot.verify("Bearer " + _token(rsa_key))
    assert claims["iss"] == ISSUER and claims["aud"] == APP_ID


@pytest.mark.parametrize("change,reason", [
    ({"iss": "https://sts.windows.net/someone-else/"}, "issuer"),
    ({"aud": "00000000-0000-0000-0000-000000000000"}, "audience"),
    ({"exp_delta": -3600}, "expired"),
    ({"kid": "unknown"}, "key"),
    ({"alg": "HS256"}, "algorithm"),
])
def test_a_request_that_fails_any_check_is_refused(rsa_key, bot, change, reason):
    from maverick_dashboard.teams_bot import TeamsAuthError

    with pytest.raises(TeamsAuthError):
        bot.verify("Bearer " + _token(rsa_key, **change))


def test_a_request_signed_by_another_key_is_refused(bot):
    from maverick_dashboard.teams_bot import TeamsAuthError

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TeamsAuthError):
        bot.verify("Bearer " + _token(other))


def test_a_missing_or_malformed_header_is_refused(bot):
    from maverick_dashboard.teams_bot import TeamsAuthError

    for header in ("", "Basic abc", "Bearer ", "Bearer not-a-jwt"):
        with pytest.raises(TeamsAuthError):
            bot.verify(header)


def test_a_key_not_endorsed_for_teams_is_refused(rsa_key, env, world, transport):
    from maverick_dashboard import teams_bot

    other = teams_bot.build_bot(transport=transport, world=world,
                                keys=teams_bot.SigningKeys(jwks=_jwks(rsa_key, endorsements=("webchat",))))
    with pytest.raises(teams_bot.TeamsAuthError):
        other.verify("Bearer " + _token(rsa_key))


def test_a_rotated_key_is_fetched_once_then_trusted_and_a_failed_fetch_refuses(rsa_key):
    from maverick_dashboard.teams_bot import SigningKeys, TeamsAuthError, verify_bot_token

    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    documents = {"https://login.botframework.com/v1/.well-known/openidconfiguration":
                 {"jwks_uri": "https://login.botframework.com/v1/.well-known/keys"},
                 "https://login.botframework.com/v1/.well-known/keys": _jwks(new_key, kid="k2")}
    fetches: list[str] = []

    def fetch(url):
        fetches.append(url)
        return documents[url]

    keys = SigningKeys(fetch, jwks=_jwks(rsa_key, kid="k1"))
    assert verify_bot_token(_token(new_key, kid="k2"), app_id=APP_ID, keys=keys,
                            required_endorsement="msteams")["aud"] == APP_ID
    assert len(fetches) == 2
    # An unknown key right after a refresh is refused without fetching again.
    with pytest.raises(TeamsAuthError):
        verify_bot_token(_token(new_key, kid="k3"), app_id=APP_ID, keys=keys)
    assert len(fetches) == 2

    def broken(url):
        raise OSError("network down")

    with pytest.raises(TeamsAuthError):
        verify_bot_token(_token(new_key, kid="k9"), app_id=APP_ID, keys=SigningKeys(broken))


# ------------------------------------------------------- the messaging route


@pytest.fixture
def client(env, bot, monkeypatch):
    from maverick_dashboard import teams_bot
    from maverick_dashboard.app import app

    monkeypatch.setattr(teams_bot, "build_bot", lambda **kw: bot)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def test_the_route_refuses_unsigned_and_badly_signed_requests_and_decides_nothing(
        client, world, rsa_key, monkeypatch):
    from maverick_dashboard import approval_decisions

    calls = []
    monkeypatch.setattr(approval_decisions, "decide_from_channel", lambda **kw: calls.append(kw))
    _link("alice")
    approval_id, binding = _park(world)
    body = _invoke("approve", approval_id, binding)
    assert client.post("/webhook/teams", json=body).status_code == 403
    for token in (_token(rsa_key, aud="somebody-else"), _token(rsa_key, exp_delta=-3600),
                  _token(rsa_key, iss="https://evil.example")):
        assert client.post("/webhook/teams", json=body,
                           headers={"Authorization": "Bearer " + token}).status_code == 403
    assert calls == [] and _status(world, approval_id) == "pending"


def test_a_signed_request_for_another_service_or_channel_is_refused(client, world, rsa_key):
    _link("alice")
    approval_id, binding = _park(world)
    auth = {"Authorization": "Bearer " + _token(rsa_key)}
    body = _invoke("approve", approval_id, binding)
    assert client.post("/webhook/teams", json={**body, "serviceUrl": "https://elsewhere.example/"},
                       headers=auth).status_code == 403
    assert client.post("/webhook/teams", json={**body, "channelId": "slack"}, headers=auth).status_code == 403
    assert client.post("/webhook/teams", content=b"not json", headers=auth).status_code == 400
    assert _status(world, approval_id) == "pending"


def test_a_signed_click_decides_the_request_and_answers_with_the_updated_card(client, world, rsa_key):
    _link("alice")
    approval_id, binding = _park(world)
    answer = client.post("/webhook/teams", json=_invoke("approve", approval_id, binding),
                         headers={"Authorization": "Bearer " + _token(rsa_key)})
    assert answer.status_code == 200, answer.text
    assert answer.json()["type"] == "application/vnd.microsoft.card.adaptive"
    assert "Approved by" in answer.text and "Action.Execute" not in answer.text
    assert _status(world, approval_id) == "approved"


def test_the_route_is_closed_when_teams_is_off(env, world, rsa_key, monkeypatch):
    from maverick_dashboard.app import app

    env.configure(enabled=False)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        assert c.post("/webhook/teams", json={},
                      headers={"Authorization": "Bearer " + _token(rsa_key)}).status_code == 404


# ------------------------------------------------ deciding from a card click


def test_approve_goes_through_the_page_rules_and_every_copy_of_the_card_is_updated(
        env, world, bot, transport):
    from maverick import teams_identity

    for who in ("alice", "bob"):
        _link(who)
        teams_identity.remember_conversation(AAD[who], {
            "service_url": SERVICE_URL, "conversation_id": f"19:{who}", "tenant_id": TENANT})
    approval_id, binding = _park(world)
    from maverick_dashboard import teams_bot

    teams_bot.post_approval(approval_id, bot=bot, world=world)
    assert len(transport.sent("POST", "/activities")) == 2

    answer = bot.handle_invoke(teams_bot.parse_activity(_invoke("approve", approval_id, binding),
                                                        bot_id=bot.connector.bot_id))
    assert "Approved by" in _message_text(answer)
    approval = world.get_approval(approval_id)
    assert approval.status == "approved" and approval.decided_by == "user:alice"
    updates = transport.sent("PUT", "/activities/")
    assert len(updates) == 2
    for call in updates:
        text = json.dumps(call["json"])
        assert "Approved by" in text and "alice" in text and "Action.Execute" not in text
    # The record of cards is cleared once they show the outcome.
    assert teams_bot._peek_cards(approval_id) == []


def test_reject_decides_it_and_nothing_runs(env, world, bot):
    from maverick_dashboard import teams_bot

    _link("alice")
    approval_id, binding = _park(world)
    answer = bot.handle_invoke(teams_bot.parse_activity(_invoke("reject", approval_id, binding),
                                                        bot_id=bot.connector.bot_id))
    assert "Rejected by" in _message_text(answer)
    assert _status(world, approval_id) == "denied"


def _click(bot, *args, **kwargs):
    from maverick_dashboard import teams_bot

    return bot.handle_invoke(teams_bot.parse_activity(_invoke(*args, **kwargs), bot_id=bot.connector.bot_id))


def test_teams_renders_only_the_current_card_after_recording_the_vote(env, world, bot, monkeypatch):
    from maverick.approval_cards import APPROVAL_DETAIL_PREFIX
    from maverick.safety import secret_detector
    from maverick_dashboard import approval_decisions

    _link("alice")
    approval_id, binding = _park(world)
    project = approval_decisions.approval_view
    states = []
    envelope_scans = []
    redact = secret_detector.redact

    def track(*args, **kwargs):
        view = project(*args, **kwargs)
        states.append(view["approval"]["status"])
        return view

    def no_envelope(text):
        if text.startswith(APPROVAL_DETAIL_PREFIX):
            envelope_scans.append(True)
        return redact(text)

    monkeypatch.setattr(approval_decisions, "approval_view", track)
    monkeypatch.setattr(secret_detector, "redact", no_envelope)
    assert "Rejected by" in _message_text(_click(bot, "reject", approval_id, binding))
    assert states == ["denied"]
    assert envelope_scans == []


def test_a_card_for_a_changed_request_is_refused_on_the_card_and_stays_open(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world)
    answer = _click(bot, "approve", approval_id, "f" * 64)
    assert "review the current approval card" in _message_text(answer) or "no longer" in _message_text(answer) \
        or "stale" in _message_text(answer).lower() or "changed" in _message_text(answer).lower()
    assert "Action.Execute" in _message_text(answer)  # buttons stay: nothing was decided
    assert _status(world, approval_id) == "pending"


def test_a_high_risk_approval_needs_the_acknowledgement_and_the_server_enforces_it(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world, risk="high")
    refused = _click(bot, "approve", approval_id, binding, activity_id="a1")
    assert "read what this action will do" in _message_text(refused)
    assert _status(world, approval_id) == "pending"
    still_no = _click(bot, "approve", approval_id, binding, activity_id="a2", acknowledged="false")
    assert "read what this action will do" in _message_text(still_no)
    assert _status(world, approval_id) == "pending"
    done = _click(bot, "approve", approval_id, binding, activity_id="a3", acknowledged="true")
    assert "Approved by" in _message_text(done) and _status(world, approval_id) == "approved"


def test_a_critical_approval_also_needs_the_typed_word(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world, risk="critical")
    missing = _click(bot, "approve", approval_id, binding, activity_id="a1", acknowledged="true")
    assert "Type APPROVE" in _message_text(missing) and _status(world, approval_id) == "pending"
    done = _click(bot, "approve", approval_id, binding, activity_id="a2", acknowledged="true",
                  confirmation="approve")
    assert _status(world, approval_id) == "approved" and "Approved by" in _message_text(done)


def test_rejecting_a_high_risk_request_needs_no_acknowledgement(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world, risk="high")
    _click(bot, "reject", approval_id, binding)
    assert _status(world, approval_id) == "denied"


def test_the_person_who_asked_leaves_a_high_risk_approval_to_someone_else(env, world, bot):
    _link("alice")
    _link("bob")
    approval_id, binding = _park(world, risk="high", requested_by="user:alice")
    refused = _click(bot, "approve", approval_id, binding, acknowledged="true")
    assert "someone else must approve" in _message_text(refused)
    assert _status(world, approval_id) == "pending"
    other = _click(bot, "approve", approval_id, binding, who="bob", activity_id="inv-2", acknowledged="true")
    assert "Approved by" in _message_text(other) and _status(world, approval_id) == "approved"


def test_a_person_without_the_approve_permission_is_refused_and_it_is_audited(env, world, bot, monkeypatch):
    from maverick_dashboard import approval_decisions

    _link("carol")
    approval_id, binding = _park(world)
    events = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: events.append((kind, kw)) or True)
    answer = _click(bot, "approve", approval_id, binding, who="carol")
    assert "can't open this request" in _message_text(answer) or "can't decide" in _message_text(answer)
    assert _status(world, approval_id) == "pending"
    # The decision path itself refuses too, whatever the bot checks first.
    with pytest.raises(approval_decisions.ApprovalDecisionRefused) as refused:
        approval_decisions.decide_from_channel(
            approval_id=approval_id, status="approved", principal="user:carol", binding=binding,
            channel="teams", world=world)
    assert "approver role" in refused.value.detail
    assert any(kw.get("action") == "approval.decide" and kw.get("principal") == "user:carol"
               for _kind, kw in events)


def test_a_person_who_cannot_open_the_request_cannot_decide_it(env, world, bot):
    """Another person's private work is not an outside agent's request: only its owner reads it."""
    from maverick_dashboard import approval_decisions

    _link("alice")
    approval_id, binding = _park(world, provenance=None, requested_by="user:dave")
    with pytest.raises(approval_decisions.ApprovalDecisionRefused) as refused:
        approval_decisions.decide_from_channel(
            approval_id=approval_id, status="approved", principal="user:alice", binding=binding,
            channel="teams", world=world)
    assert "can't open this request" in refused.value.detail
    assert _status(world, approval_id) == "pending"


def test_a_protected_settings_change_is_decided_on_the_web_only(env, world, bot):
    from maverick_dashboard import approval_decisions

    _link("alice")
    approval_id, binding = _park(world, provenance="settings_quorum", requested_by="user:alice")
    with pytest.raises(approval_decisions.ApprovalDecisionRefused) as refused:
        approval_decisions.decide_from_channel(
            approval_id=approval_id, status="denied", principal="user:alice", binding=binding,
            channel="teams", world=world)
    assert "Approvals page" in refused.value.detail


def test_an_unlinked_account_is_told_so_and_decides_nothing(env, world, bot):
    approval_id, binding = _park(world)
    answer = _click(bot, "approve", approval_id, binding)
    assert "isn't linked" in _message_text(answer)
    assert _status(world, approval_id) == "pending"


def test_a_request_decided_elsewhere_is_shown_as_decided_with_no_buttons(env, world, bot):
    from maverick_dashboard.app import app

    _link("alice")
    approval_id, binding = _park(world)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as web:
        decided = web.post(f"/api/v1/approvals/{approval_id}/deny", json={})
        assert decided.status_code == 204, decided.text
    answer = _click(bot, "approve", approval_id, binding)
    text = _message_text(answer)
    assert "already decided" in text and "Rejected" in text and "Action.Execute" not in text
    assert _status(world, approval_id) == "denied"


def test_a_decision_on_the_web_page_updates_the_cards_posted_in_teams(env, world, bot, transport, monkeypatch):
    from maverick import teams_identity
    from maverick_dashboard import teams_bot
    from maverick_dashboard.app import app

    _link("alice")
    teams_identity.remember_conversation(AAD["alice"], {
        "service_url": SERVICE_URL, "conversation_id": "19:alice", "tenant_id": TENANT})
    monkeypatch.setattr(teams_bot, "build_bot", lambda **kw: bot)
    approval_id, _binding = _park(world)
    teams_bot.post_approval(approval_id, bot=bot, world=world)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as web:
        assert web.post(f"/api/v1/approvals/{approval_id}/deny", json={}).status_code == 204
    (update,) = transport.sent("PUT", "/activities/")
    assert "Rejected" in json.dumps(update["json"]) and "Action.Execute" not in json.dumps(update["json"])


def test_a_redelivered_click_is_not_decided_twice(env, world, bot, monkeypatch):
    from maverick_dashboard import approval_decisions

    _link("alice")
    approval_id, binding = _park(world)
    real = approval_decisions.decide_from_channel
    seen = []
    monkeypatch.setattr(approval_decisions, "decide_from_channel",
                        lambda **kw: seen.append(kw) or real(**kw))
    first = _click(bot, "approve", approval_id, binding, activity_id="same-click")
    again = _click(bot, "approve", approval_id, binding, activity_id="same-click")
    assert len(seen) == 1
    assert "Approved by" in _message_text(first) and "Approved by" in _message_text(again)
    assert _status(world, approval_id) == "approved"


def test_a_click_that_failed_unexpectedly_can_be_retried(env, world, bot, monkeypatch):
    from maverick_dashboard import approval_decisions

    _link("alice")
    approval_id, binding = _park(world)
    real = approval_decisions.decide_from_channel

    def broken(**kw):
        raise RuntimeError("database went away")

    monkeypatch.setattr(approval_decisions, "decide_from_channel", broken)
    failed = _click(bot, "approve", approval_id, binding, activity_id="retry-me")
    assert failed["statusCode"] == 500 and "database" not in json.dumps(failed)
    monkeypatch.setattr(approval_decisions, "decide_from_channel", real)
    done = _click(bot, "approve", approval_id, binding, activity_id="retry-me")
    assert "Approved by" in _message_text(done)


# --------------------------------------------------- who is allowed to click


def test_a_click_from_another_tenant_is_ignored(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world)
    status, answer = bot.handle(_invoke("approve", approval_id, binding, tenant=OTHER_TENANT), CLAIMS)
    assert status == 200 and "can't use this bot" in str(answer)
    assert _status(world, approval_id) == "pending"


def test_extra_allowed_tenants_are_accepted(env, world, transport, rsa_key):
    from maverick_dashboard import teams_bot

    env.configure(f'allowed_tenants = ["{OTHER_TENANT}"]')
    other = teams_bot.build_bot(transport=transport, world=world,
                                keys=teams_bot.SigningKeys(jwks=_jwks(rsa_key)))
    _link("alice")
    approval_id, binding = _park(world)
    _status_code, answer = other.handle(_invoke("approve", approval_id, binding, tenant=OTHER_TENANT), CLAIMS)
    assert _status(world, approval_id) == "approved"


def test_only_listed_people_may_click_when_the_settings_list_them(env, world, transport, rsa_key):
    from maverick_dashboard import teams_bot

    env.configure(f'allowed_users = ["{AAD["bob"]}"]')
    limited = teams_bot.build_bot(transport=transport, world=world,
                                  keys=teams_bot.SigningKeys(jwks=_jwks(rsa_key)))
    _link("alice")
    approval_id, binding = _park(world)
    _status_code, answer = limited.handle(_invoke("approve", approval_id, binding), CLAIMS)
    assert "not allowed" in str(answer) and _status(world, approval_id) == "pending"


def test_a_click_without_an_entra_object_id_is_refused(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world)
    activity = _invoke("approve", approval_id, binding)
    del activity["from"]["aadObjectId"]
    _status_code, answer = bot.handle(activity, CLAIMS)
    assert "not allowed" in str(answer) and _status(world, approval_id) == "pending"


def test_an_unknown_button_or_missing_request_number_decides_nothing(env, world, bot):
    _link("alice")
    approval_id, binding = _park(world)
    assert "isn't recognised" in _message_text(_click(bot, "delete", approval_id, binding))
    bad = _invoke("approve", approval_id, binding, activity_id="inv-9")
    bad["value"]["action"]["data"]["approval_id"] = "x"
    from maverick_dashboard import teams_bot

    answer = bot.handle_invoke(teams_bot.parse_activity(bad, bot_id=bot.connector.bot_id))
    assert "missing its request number" in _message_text(answer)
    assert _status(world, approval_id) == "pending"


# --------------------------------------------------------- posting the cards


def _reachable(*people):
    from maverick import teams_identity

    for who in people:
        _link(who)
        teams_identity.remember_conversation(AAD[who], {
            "service_url": SERVICE_URL, "conversation_id": f"19:{who}", "tenant_id": TENANT})


def test_the_card_goes_to_linked_approvers_and_to_nobody_else(env, world, bot, transport):
    from maverick_dashboard import teams_bot

    _reachable("alice", "bob", "carol")  # carol is a viewer: no approve permission
    _link("dave")  # an operator who has never talked to the bot: a chat is created for him
    approval_id, _binding = _park(world)
    results = teams_bot.post_approval(approval_id, bot=bot, world=world)
    assert {r["to"] for r in results} == {"user:alice", "user:bob", "user:dave"} and all(r["ok"] for r in results)
    posts = transport.sent("POST", "/activities")
    conversations = [c for c in transport.calls if c["url"].endswith("/v3/conversations")]
    assert len(posts) == 3 and len(conversations) == 1
    assert conversations[0]["json"]["members"] == [{"id": AAD["dave"]}]
    assert conversations[0]["json"]["tenantId"] == TENANT
    card = posts[0]["json"]["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    content = card["content"]
    assert content["version"] == "1.5"
    verbs = [a["verb"] for a in content["actions"] if a["type"] == "Action.Execute"]
    assert verbs == ["approve", "reject"]
    text = json.dumps(content)
    assert "External agent helpdesk" in text and "Asked by" in text and "ai agent" in text
    assert all(call["headers"].get("Authorization") == "Bearer bot-token-1" for call in transport.calls
               if "oauth2" not in call["url"])
    assert teams_bot._peek_cards(approval_id) and len(teams_bot._peek_cards(approval_id)) == 3


def test_the_person_who_asked_is_not_sent_a_card_they_cannot_act_on(env, world, bot, transport):
    from maverick_dashboard import teams_bot

    _reachable("alice", "bob")
    approval_id, _binding = _park(world, risk="high", requested_by="user:alice")
    results = teams_bot.post_approval(approval_id, bot=bot, world=world)
    assert [r["to"] for r in results] == ["user:bob"]


def test_one_unreachable_person_does_not_stop_the_others(env, world, bot, transport):
    from maverick_dashboard import teams_bot

    _reachable("alice", "bob")
    transport.responses["19%3Aalice/activities"] = (403, {"error": "app not installed"})
    approval_id, _binding = _park(world)
    results = {r["to"]: r for r in teams_bot.post_approval(approval_id, bot=bot, world=world)}
    assert results["user:bob"]["ok"] is True
    assert results["user:alice"]["ok"] is False and "installed" in results["user:alice"]["detail"]


def test_an_outside_agents_request_also_goes_to_the_channel_but_private_work_does_not(
        env, world, transport, rsa_key):
    from maverick_dashboard import teams_bot

    env.configure('channel_id = "19:chan@thread.tacv2"')
    channel_bot = teams_bot.build_bot(transport=transport, world=world,
                                      keys=teams_bot.SigningKeys(jwks=_jwks(rsa_key)))
    agent_id, _ = _park(world)
    results = teams_bot.post_approval(agent_id, bot=channel_bot, world=world)
    assert [r["to"] for r in results] == ["channel"] and results[0]["ok"]
    (post,) = [c for c in transport.calls if c["url"].endswith("/v3/conversations")]
    assert post["json"]["channelData"]["channel"] == {"id": "19:chan@thread.tacv2"}
    assert post["json"]["activity"]["attachments"]
    transport.calls.clear()
    private_id, _ = _park(world, provenance=None, requested_by="user:dave")
    assert teams_bot.post_approval(private_id, bot=channel_bot, world=world) == []
    assert transport.calls == []


def test_the_agents_own_words_show_only_when_the_setting_allows_it(env, world, bot, monkeypatch):
    from maverick_dashboard import teams_bot

    _reachable("alice")
    approval_id, _binding = _park(world, agent_says="Please wire the money today")
    seen = []
    for shown in (True, False):
        monkeypatch.setattr(teams_bot, "show_request_detail", lambda shown=shown: shown)
        transport = bot.connector._transport
        transport.calls.clear()
        teams_bot._forget_cards(approval_id)
        teams_bot.post_approval(approval_id, bot=bot, world=world)
        seen.append(json.dumps(transport.sent("POST", "/activities")[0]["json"]))
    assert "wire the money today" in seen[0]
    assert "wire the money today" not in seen[1] and "Resolved risk" in seen[1]


def test_an_agents_text_cannot_dress_up_as_card_formatting(env, world, bot, transport):
    from maverick_dashboard import teams_bot

    _reachable("alice")
    approval_id, _binding = _park(world, agent_says="[Approve here](https://evil.example) **now**")
    teams_bot.post_approval(approval_id, bot=bot, world=world)
    text = json.dumps(transport.sent("POST", "/activities")[0]["json"])
    assert "[Approve here](https://evil.example)" not in text and "\\\\[Approve here" in text


def test_a_high_risk_card_carries_the_toggle_and_reject_carries_no_inputs(env, world, bot):
    from maverick_dashboard import approval_decisions, teams_cards

    _reachable("alice")
    for risk, extra in (("medium", 0), ("high", 1), ("critical", 2)):
        approval_id, _binding = _park(world, risk=risk)
        view = approval_decisions.approval_view(approval_id, world=world)
        card = teams_cards.approval_card(view)
        inputs = [item for item in card["body"] if item["type"].startswith("Input.")]
        assert len(inputs) == extra
        reject = next(a for a in card["actions"] if a.get("verb") == "reject")
        assert reject["associatedInputs"] == "none"
        assert card["version"] == "1.5"


def test_an_expired_or_unreadable_request_offers_no_approve_button(env, world):
    from maverick_dashboard import approval_decisions, teams_cards

    approval_id, _binding = _park(world, expires_in=-10)
    card = teams_cards.approval_card(approval_decisions.approval_view(approval_id, world=world))
    assert [a["verb"] for a in card["actions"]] == ["reject"]


def test_nothing_is_posted_when_teams_is_off_or_incomplete(env, world, transport, monkeypatch):
    from maverick import approval_notify

    spawned = []
    monkeypatch.setattr(approval_notify, "_spawn", lambda *a: spawned.append(a))
    env.configure(enabled=False)
    _park(world)
    assert spawned == []
    env.configure()
    monkeypatch.delenv("TEAMS_BOT_SECRET")
    _park(world)
    assert spawned == []


def test_parking_a_request_posts_its_card_without_waiting_for_teams(env, world, bot, transport, monkeypatch):
    from maverick import approval_notify

    spawned = []
    monkeypatch.setattr(approval_notify, "_spawn", lambda function, *args: spawned.append(args))
    approval_id, _binding = _park(world)
    assert spawned == [("post_approval", approval_id, world)]


def test_a_request_parked_while_people_are_linked_reaches_them_end_to_end(env, world, bot, transport):
    _reachable("alice", "bob")
    _BACKGROUND["post"] = True
    approval_id, _binding = _park(world)
    assert {call["url"].split("/conversations/")[1].split("/")[0] for call in transport.sent("POST")} \
        == {"19%3Aalice", "19%3Abob"}


# ------------------------------------------------------ links and who is who


def test_a_link_by_user_principal_name_is_pinned_to_the_object_id_when_the_person_writes(
        env, world, bot, transport):
    from maverick import teams_identity
    from maverick_dashboard import teams_bot

    teams_identity.link("alice@example.com", "user:alice", actor="admin")
    assert teams_identity.principal_for(AAD["alice"]) is None
    transport.responses["/members/"] = (200, {"userPrincipalName": "Alice@Example.com"})
    message = {"type": "message", "id": "m1", "channelId": "msteams", "serviceUrl": SERVICE_URL,
               "text": "hello", "from": {"id": "29:alice", "aadObjectId": AAD["alice"]},
               "conversation": {"id": "19:alice", "conversationType": "personal", "tenantId": TENANT},
               "recipient": {"id": f"28:{APP_ID}"}, "channelData": {"tenant": {"id": TENANT}}}
    bot.handle(message, CLAIMS)
    assert teams_identity.principal_for(AAD["alice"]) == "user:alice"
    assert teams_identity.principal_for("alice@example.com") is None
    assert teams_identity.conversation_for(AAD["alice"])["conversation_id"] == "19:alice"
    assert teams_bot  # the bot answered the message with a plain reply
    assert "only send approval requests" in json.dumps(transport.sent("POST", "/activities")[0]["json"])


def test_with_entra_sign_in_a_person_who_signed_in_is_recognised_without_any_link(env, world, bot, monkeypatch):
    from maverick import teams_identity
    from maverick_dashboard import subject_directory

    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)
    assert teams_identity.resolve_principal(AAD["alice"]) is None
    subject_directory.record_login("subject-of-alice", ["alice@example.com", AAD["alice"]])
    assert teams_identity.resolve_principal(AAD["alice"]) == "user:subject-of-alice"
    assert teams_identity.resolve_principal("someone-else", "alice@example.com") == "user:subject-of-alice"
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    assert teams_identity.resolve_principal(AAD["alice"]) is None


def test_a_recognised_person_who_has_written_to_the_bot_is_sent_cards(env, world, bot, transport, monkeypatch):
    from maverick import teams_identity
    from maverick_dashboard import subject_directory, teams_bot

    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)
    subject_directory.record_login("alice", [AAD["alice"]])
    teams_identity.remember_conversation(AAD["alice"], {
        "service_url": SERVICE_URL, "conversation_id": "19:alice", "tenant_id": TENANT})
    approval_id, _binding = _park(world)
    assert [r["to"] for r in teams_bot.post_approval(approval_id, bot=bot, world=world)] == ["user:alice"]


def test_the_link_code_works_without_entra_sign_in_once_and_never_with_it(env, monkeypatch):
    from maverick import teams_identity

    code = teams_identity.issue_link_code("user:alice", actor="admin")
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)
    assert teams_identity.redeem_link_code(code, AAD["alice"]) is None
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    assert teams_identity.redeem_link_code("WRONG123", AAD["alice"]) is None
    assert teams_identity.redeem_link_code(code, AAD["alice"]) == "user:alice"
    assert teams_identity.redeem_link_code(code, AAD["bob"]) is None  # used once
    assert teams_identity.principal_for(AAD["alice"]) == "user:alice"
    assert code not in (env.path / "teams-identities.json").read_text()  # only its hash is kept


def test_a_person_links_their_account_by_sending_the_code_to_the_bot(env, world, bot, transport):
    from maverick import teams_identity

    code = teams_identity.issue_link_code("user:alice", actor="admin")
    message = {"type": "message", "id": "m2", "channelId": "msteams", "serviceUrl": SERVICE_URL,
               "text": f"link {code}", "from": {"id": "29:alice", "aadObjectId": AAD["alice"]},
               "conversation": {"id": "19:alice", "conversationType": "personal", "tenantId": TENANT},
               "recipient": {"id": f"28:{APP_ID}"}, "channelData": {"tenant": {"id": TENANT}}}
    bot.handle(message, CLAIMS)
    assert teams_identity.principal_for(AAD["alice"]) == "user:alice"
    assert "now linked" in json.dumps(transport.sent("POST", "/activities")[0]["json"])


def test_identity_input_is_validated():
    from maverick import teams_identity

    for bad in ("", "has space", "a" * 400, "x;y"):
        with pytest.raises(teams_identity.TeamsIdentityError):
            teams_identity.normalize_teams_id(bad)
    assert teams_identity.normalize_teams_id(" Alice@Example.COM ") == "alice@example.com"
    assert teams_identity.normalize_principal("alice") == "user:alice"
    with pytest.raises(teams_identity.TeamsIdentityError):
        teams_identity.normalize_principal("two words")


# ------------------------------------------------------ status, test, links


@pytest.fixture
def web(env):
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def test_the_status_says_what_is_missing_in_plain_words_and_holds_no_secret(env, web, monkeypatch):
    monkeypatch.delenv("TEAMS_BOT_SECRET")
    answer = web.get("/api/v1/teams")
    assert answer.status_code == 200
    body = answer.json()
    assert body["ready"] is False and body["secret_set"] is False
    assert "TEAMS_BOT_SECRET" in body["summary"]
    monkeypatch.setenv("TEAMS_BOT_SECRET", SECRET)
    ready = web.get("/api/v1/teams")
    assert ready.json()["ready"] is True and ready.json()["secret_set"] is True
    assert SECRET not in ready.text and APP_ID not in ready.text.replace('"app_id_set"', "")


def test_the_status_is_off_by_default(env, web):
    env.configure(enabled=False)
    body = web.get("/api/v1/teams").json()
    assert body["enabled"] is False and "turned off" in body["summary"]


def test_the_test_card_reaches_the_administrator_and_the_channel_and_reports_failures(
        env, web, transport, monkeypatch, world):
    from maverick_dashboard import teams_bot

    env.configure('channel_id = "19:chan@thread.tacv2"')
    monkeypatch.setattr(teams_bot, "default_transport", transport)
    monkeypatch.setattr(teams_bot, "caller_principal", lambda request: "user:alice")
    _reachable("alice")
    answer = web.post("/api/v1/teams/test")
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert [r["to"] for r in body["results"]] == ["you", "channel"] and all(r["ok"] for r in body["results"])
    assert body["credentials"].startswith("Microsoft accepted")
    assert SECRET not in answer.text
    assert transport.calls[0]["data"]["client_secret"] == SECRET  # only ever sent to Microsoft's sign-in


def test_the_test_says_so_when_microsoft_refuses_the_secret(env, web, transport, monkeypatch):
    from maverick_dashboard import teams_bot

    transport.responses["token"] = (401, {"error": "invalid_client", "error_description": "AADSTS7000215: x"})
    monkeypatch.setattr(teams_bot, "default_transport", transport)
    body = web.post("/api/v1/teams/test").json()
    assert "did not accept the bot's secret" in body["message"]
    assert body["results"] == [] and SECRET not in json.dumps(body)


def test_only_an_administrator_manages_teams(env, web, monkeypatch):
    from maverick_dashboard import auth, teams_bot

    monkeypatch.setattr(auth, "has_permission", lambda request, permission, **kw: permission != "admin")
    for method, path in (("get", "/api/v1/teams"), ("post", "/api/v1/teams/test"),
                         ("get", "/api/v1/teams/links"), ("post", "/api/v1/teams/links"),
                         ("post", "/api/v1/teams/link-codes")):
        assert getattr(web, method)(path).status_code == 403, path
    assert teams_bot  # the same gate guards every administrator route


def test_an_administrator_links_and_unlinks_accounts_and_issues_codes(env, web):
    linked = web.post("/api/v1/teams/links", json={"teams_id": AAD["alice"], "principal": "alice"})
    assert linked.status_code == 200 and linked.json()["principal"] == "user:alice"
    assert web.post("/api/v1/teams/links", json={"teams_id": "bad id", "principal": "alice"}).status_code == 422
    listed = web.get("/api/v1/teams/links").json()["links"]
    assert listed[0]["teams_id"] == AAD["alice"] and listed[0]["kind"] == "object id"
    code = web.post("/api/v1/teams/link-codes", json={"principal": "bob"})
    assert code.status_code == 200 and len(code.json()["code"]) == 8
    assert code.headers["cache-control"] == "no-store"
    assert web.delete(f"/api/v1/teams/links/{AAD['alice']}").status_code == 200
    assert web.delete(f"/api/v1/teams/links/{AAD['alice']}").status_code == 404


def test_codes_are_not_issued_while_entra_sign_in_is_on(env, web, monkeypatch):
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)
    assert web.post("/api/v1/teams/link-codes", json={"principal": "bob"}).status_code == 409


def test_a_person_sees_whether_their_account_is_known(env, web, monkeypatch):
    from maverick_dashboard import teams_bot

    monkeypatch.setattr(teams_bot, "caller_principal", lambda request: "user:alice")
    assert web.get("/api/v1/teams/me").json()["linked"] is False
    _reachable("alice")
    assert web.get("/api/v1/teams/me").json()["linked"] is True


# ---------------------------------------------------------------- secrets


def test_no_secret_token_or_signed_request_is_logged_or_returned(
        env, world, bot, transport, rsa_key, client, caplog):
    caplog.set_level(logging.DEBUG)
    _reachable("alice")
    approval_id, binding = _park(world, risk="high")
    from maverick_dashboard import teams_bot

    teams_bot.post_approval(approval_id, bot=bot, world=world)
    signed = _token(rsa_key)
    answers = [
        client.post("/webhook/teams", json=_invoke("approve", approval_id, binding),
                    headers={"Authorization": "Bearer " + signed}),
        client.post("/webhook/teams", json={}, headers={"Authorization": "Bearer " + signed[:-5] + "xxxxx"}),
        client.post("/webhook/teams", json={}),
        client.get("/api/v1/teams"),
    ]
    everything = caplog.text + "".join(a.text for a in answers)
    for secret in (SECRET, "bot-token-1", signed):
        assert secret not in everything
    assert SECRET not in json.dumps(teams_bot.status())


def test_the_secret_comes_from_the_named_variable_and_a_missing_one_means_not_ready(env, monkeypatch):
    from maverick.approval_notify import teams_approvals_enabled, teams_secret, teams_settings

    env.configure('app_secret_env = "MY_OWN_VARIABLE"')
    assert teams_settings()["app_secret_env"] == "MY_OWN_VARIABLE"
    assert teams_secret() == "" and teams_approvals_enabled() is False
    monkeypatch.setenv("MY_OWN_VARIABLE", "other-secret")  # pragma: allowlist secret
    assert teams_secret() == "other-secret" and teams_approvals_enabled() is True
    assert "other-secret" not in (env.path / "config.toml").read_text()


def test_outbound_calls_are_https_only_and_go_through_the_guarded_client(monkeypatch):
    from maverick_dashboard import teams_bot

    with pytest.raises(teams_bot.TeamsSendError):
        teams_bot.default_transport("GET", "http://smba.trafficmanager.net/teams/v3/x")
    seen = []

    class FakeResponse:
        status_code = 200

        def iter_bytes(self, chunk_size=0):
            yield b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class FakeClient:
        def stream(self, method, url, **kw):
            seen.append((method, url))
            return FakeResponse()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("maverick.tools._ssrf.safe_client", lambda url, **kw: seen.append(kw) or FakeClient())
    assert teams_bot.default_transport("GET", "https://login.botframework.com/x") == (200, {"ok": True})
    assert seen[0]["timeout"] == teams_bot.HTTP_TIMEOUT


def test_the_route_needs_no_browser_origin_or_dashboard_sign_in_because_the_signature_is_the_credential(
        env, world, bot, rsa_key, monkeypatch):
    """Teams sends no Origin header and holds no dashboard credential, even when
    the dashboard requires a token for everything else."""
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token-for-test")  # pragma: allowlist secret
    _link("alice")
    approval_id, binding = _park(world)
    with TestClient(app, base_url="https://secondshift.example") as bare:
        assert bare.get("/api/v1/teams").status_code in (401, 403)
        unsigned = bare.post("/webhook/teams", json=_invoke("approve", approval_id, binding))
        assert unsigned.status_code == 403 and "Bot Connector" in unsigned.text
        signed = bare.post("/webhook/teams", json=_invoke("approve", approval_id, binding),
                           headers={"Authorization": "Bearer " + _token(rsa_key)})
        assert signed.status_code == 200, signed.text
    assert _status(world, approval_id) == "approved"


def test_the_teams_app_package_is_built_from_the_template(tmp_path):
    import importlib.util
    import zipfile
    from pathlib import Path

    folder = Path(__file__).resolve().parents[2] / "teams-app"
    spec = importlib.util.spec_from_file_location("build_teams_package", folder / "build_package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    package = module.build(APP_ID, "SecondShift.Contoso.com", tmp_path / "app.zip")
    with zipfile.ZipFile(package) as archive:
        assert sorted(archive.namelist()) == ["color.png", "manifest.json", "outline.png"]
        manifest = json.loads(archive.read("manifest.json"))
        assert archive.read("color.png")[:8] == b"\x89PNG\r\n\x1a\n"
    assert manifest["bots"][0]["botId"] == APP_ID and manifest["id"] == APP_ID
    assert manifest["validDomains"] == ["secondshift.contoso.com"]
    assert manifest["bots"][0]["scopes"] == ["personal", "team"] and "{{" not in json.dumps(manifest)
    for bad in ("not-a-guid", ""):
        with pytest.raises(SystemExit):
            module.render(bad, "secondshift.contoso.com")
    with pytest.raises(SystemExit):
        module.render(APP_ID, "https://secondshift.contoso.com/path")


# ---------------------------------------------------------------- Postgres


def test_with_postgres_links_are_kept_there_and_a_damaged_record_is_refused(env, records_in_postgres):
    import psycopg

    from maverick import teams_identity

    teams_identity.link(AAD["alice"], "user:alice", actor="admin")
    assert teams_identity.principal_for(AAD["alice"]) == "user:alice"
    assert not teams_identity.store_path().exists()
    with psycopg.connect(records_in_postgres) as db:
        cur = db.execute(
            "UPDATE second_shift_keyed_records SET body='[1]' WHERE address='teams-identities.json' "
            "AND name='links' AND entry_key=%s", (AAD["alice"],),
        )
        assert cur.rowcount == 1
    with pytest.raises(teams_identity.TeamsIdentityError):
        teams_identity.list_links()
    with pytest.raises(teams_identity.TeamsIdentityError):
        teams_identity.principal_for(AAD["alice"])
    with psycopg.connect(records_in_postgres) as db:
        assert db.execute("SELECT body FROM second_shift_keyed_records WHERE address='teams-identities.json' "
                          "AND name='links' AND entry_key=%s", (AAD["alice"],)).fetchone() == ("[1]",)


def test_with_postgres_the_cards_the_bot_posted_are_kept_there(env, records_in_postgres):
    from maverick_dashboard import teams_bot
    from tests.new.conftest import saved_records

    teams_bot._remember_cards(7, [{"conversation_id": "19:alice", "activity_id": "a1"}])
    assert teams_bot._peek_cards(7) == [{"conversation_id": "19:alice", "activity_id": "a1"}]
    assert teams_bot._forget_cards(7) == [{"conversation_id": "19:alice", "activity_id": "a1"}]
    assert teams_bot._peek_cards(7) == []
    assert not (env.path / "teams-cards.json").exists()
    assert "teams-cards.json" in saved_records(records_in_postgres)
