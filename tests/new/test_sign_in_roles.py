"""Roles from the sign-in token: ``[auth.oidc] role_claim`` and ``[auth.oidc.role_map]``.

Hermetic. Every token is minted here with a local RSA key and checked by the
real ``maverick.oidc.verify_oidc_token`` against a stand-in key endpoint, so a
role is only ever read from a token whose signature, issuer and audience
verified. The browser tests run the real ``/auth/login`` and ``/auth/callback``
routes; only the code-for-token exchange (the one network call) is replaced.

The order under test, for a signed-in person:
administrator named in settings -> role stored for that person -> role from
their own sign-in claim -> the default role.
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import logging
import os
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException, Request, WebSocket
from fastapi.testclient import TestClient

jwt = pytest.importorskip("jwt", reason="sign-in needs PyJWT")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

ISSUER = "https://login.example.test/contoso/v2.0"
AUDIENCE = "app-client-id"
SESSION_SECRET = "unit-test-session-secret"  # pragma: allowlist secret
BASE = "/api/v1/agent-control-plane"
ROLE_MAP = """
[auth.oidc.role_map]
"SecondShift.Admin" = "admin"
"SecondShift.GovernanceLead" = "governance_lead"
"SecondShift.Operator" = "operator"
"SecondShift.Auditor" = "auditor"
"SecondShift.Viewer" = "viewer"
"""
#: What the ``installation`` fixture replaced, for the test that runs without it.
_UNCHANGED: dict = {}


@pytest.fixture(scope="module")
def keys():
    """Two key pairs: the identity provider's, and one it never published."""
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch, request, keys):
    """One installation with OpenID Connect sign-in on and its own settings file."""
    from maverick import _oidc_jwks, config, world_model
    from maverick.audit import signing
    from maverick_dashboard import auth, oidc_login, sign_in_roles

    # The posture CI asks for (tests/core/conftest.py does the same for core):
    # under the production posture the activity record is signed, with a key
    # that is read once per process, so it is set and forgotten per test.
    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"sign-in-roles-test:{request.node.nodeid}".encode()
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    signing._reset_injected_keypair_cache()

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name, value in {
        "MAVERICK_OIDC_ENABLED": "1", "MAVERICK_OIDC_ISSUER": ISSUER, "MAVERICK_OIDC_AUDIENCE": AUDIENCE,
        "MAVERICK_OIDC_JWKS_URI": "https://login.example.test/contoso/keys",
        "MAVERICK_OIDC_CLIENT_ID": AUDIENCE, "MAVERICK_OIDC_CLIENT_SECRET": "test-client-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_REDIRECT_URI": "http://127.0.0.1/auth/callback",
        "MAVERICK_OIDC_SESSION_SECRET": SESSION_SECRET,
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT": "https://login.example.test/contoso/authorize",
        "MAVERICK_OIDC_TOKEN_ENDPOINT": "https://login.example.test/contoso/token",
        "MAVERICK_CONTROL_PLANE": "1",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_MFA_REQUIRE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")

    class KeyEndpoint:
        """The provider's published signing keys, without the network."""

        def __init__(self, uri, **kwargs):
            pass

        def get_signing_keys(self, *, refresh):
            return [SimpleNamespace(key_id="k1", key=keys[0].public_key())]

    monkeypatch.setattr(jwt, "PyJWKClient", KeyEndpoint)
    # The workspace picker is not part of this package, and without it every
    # signed-in request stops at "tenant isolation policy unavailable". These
    # tests are about roles, so the picker answers "no workspace chosen" here;
    # test_per_person_isolation_... runs the unchanged path.
    _UNCHANGED["tenant_pin_choice"] = auth._tenant_pin_choice
    _oidc_jwks._resolvers.clear()
    oidc_login._CONSUMED_TX_IDS.clear()
    sign_in_roles._WARNED.clear()
    config.reset_config_cache()
    yield tmp_path
    _oidc_jwks._resolvers.clear()
    oidc_login._CONSUMED_TX_IDS.clear()
    sign_in_roles._WARNED.clear()
    signing._reset_injected_keypair_cache()
    config.reset_config_cache()


def _configure(tmp_path, body: str) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture
def mapped(installation):
    _configure(installation, ROLE_MAP)
    return installation


@pytest.fixture
def token(keys):
    """Mint an ID token as the provider would; ``key=1`` signs with the wrong key."""
    def mint(sub="alice", *, key=0, **claims):
        now = int(time.time())
        body = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 600, **claims}
        return jwt.encode(body, keys[key], algorithm="RS256", headers={"kid": "k1"})
    return mint


@pytest.fixture
def client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _sign_in(client, monkeypatch, token, sub="alice", *, expect=303, **claims):
    """The browser sign-in round trip; returns the signed session's payload."""
    from maverick.web_session import verify_session
    from maverick_dashboard import oidc_login

    location = client.get("/auth/login", follow_redirects=False).headers["location"]
    query = parse_qs(urlparse(location).query)
    id_token = token(sub, nonce=query["nonce"][0], **claims)

    async def exchange(url, *, cfg, code, code_verifier):
        return {"id_token": id_token}

    monkeypatch.setattr(oidc_login, "_exchange_code_for_tokens", exchange)
    response = client.get(f"/auth/callback?code=c&state={query['state'][0]}", follow_redirects=False)
    assert response.status_code == expect, response.text
    raw = client.cookies.get(oidc_login.SESSION_COOKIE)
    return verify_session(raw, SESSION_SECRET) if raw else None


def _may(client) -> set[str]:
    """What this caller is allowed to do, asked of real routes."""
    answers = {
        "view": client.get(f"{BASE}/status"),
        "audit": client.get(f"{BASE}/timeboxes"),
        "operate": client.post(f"{BASE}/principals/resume", json={"principal": "user:someone-else"}),
        "admin": client.post(f"{BASE}/timeboxes/sweep"),
    }
    for permission, response in answers.items():
        assert response.status_code in (200, 403), (permission, response.status_code, response.text)
    return {permission for permission, response in answers.items() if response.status_code == 200}


def _request(*, bearer: str | None = None, session: str | None = None, websocket: bool = False):
    """A real connection, authenticated by the real request dependency."""
    from maverick_dashboard import auth, oidc_login

    headers = [(b"host", b"127.0.0.1")]
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    if session is not None:
        headers.append((b"cookie", f"{oidc_login.SESSION_COOKIE}={session}".encode()))
    scope = {"type": "websocket" if websocket else "http", "method": "GET", "path": f"{BASE}/status",
             "scheme": "http", "headers": headers, "query_string": b"", "server": ("127.0.0.1", 80),
             "client": ("127.0.0.1", 1234)}
    connection = WebSocket(scope, receive=None, send=None) if websocket else Request(scope)
    key = "websocket" if websocket else "request"
    asyncio.run(auth.require_principal_in_request_context(**{key: connection}))
    return connection


def _store_role(principal: str, role: str) -> None:
    from maverick_dashboard import rbac

    path = rbac.store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({principal: role}), encoding="utf-8")
    path.chmod(0o600)


# ------------------------------------------------------------ the new role

def test_a_custom_role_cannot_take_the_built_in_name():
    from maverick_dashboard import rbac

    with pytest.raises(rbac.RbacStoreError):
        rbac._validate_custom_role("governance_lead", {"permissions": ["view"]})


# ------------------------------------------------------------ the settings

def test_without_a_map_nothing_is_read_from_the_claim(installation):
    from maverick_dashboard import sign_in_roles

    settings = sign_in_roles.load_settings()
    assert settings.claim == "roles" and dict(settings.role_map) == {}
    assert sign_in_roles.role_from_claims({"roles": ["admin", "SecondShift.Admin"]}) is None
    assert sign_in_roles.session_extra({"roles": ["admin"]}) == {}


def test_the_map_applies_and_the_claim_name_can_be_changed(installation):
    from maverick_dashboard import sign_in_roles

    _configure(installation, ROLE_MAP)
    assert sign_in_roles.load_settings().claim == "roles"  # the claim Entra uses for app roles
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Operator"]}) == "operator"
    assert sign_in_roles.role_from_claims({"roles": "SecondShift.Auditor"}) == "auditor"  # one value, not a list

    _configure(installation, '[auth.oidc]\nrole_claim = "app_roles"\n' + ROLE_MAP)
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Operator"]}) is None
    assert sign_in_roles.role_from_claims({"app_roles": ["SecondShift.Operator"]}) == "operator"


@pytest.mark.parametrize("claims", [
    {},
    {"roles": []},
    {"roles": None},
    {"roles": ["Something.Else"]},
    {"roles": ["secondshift.admin"]},          # values match exactly, letter case included
    {"roles": [" SecondShift.Admin "]},
    {"roles": ["admin"]},                       # a role name is not a mapped value
    {"roles": {"SecondShift.Admin": True}},     # not a list or a single string
    {"roles": [["SecondShift.Admin"]]},
    {"roles": [7, None, True, {"value": "SecondShift.Admin"}]},
    {"groups": ["SecondShift.Admin"]},          # another claim is never read
    {"claim_role": "admin"},
])
def test_a_value_that_is_not_in_the_map_is_ignored(mapped, claims):
    from maverick_dashboard import sign_in_roles

    assert sign_in_roles.role_from_claims(claims) is None


def test_claims_that_are_not_a_claim_set_give_no_role(mapped):
    from maverick_dashboard import sign_in_roles

    for claims in (None, [], "roles", 7):
        assert sign_in_roles.role_from_claims(claims) is None


def test_a_map_entry_naming_an_unknown_role_is_ignored_and_logged_once(installation, caplog):
    from maverick_dashboard import sign_in_roles

    _configure(installation, '[auth.oidc.role_map]\n"App.Boss" = "superuser"\n"App.Admin" = "Admin"\n'
                             '"App.Operator" = "operator"\n')
    with caplog.at_level(logging.WARNING, logger="maverick_dashboard.sign_in_roles"):
        for _ in range(3):
            assert dict(sign_in_roles.load_settings().role_map) == {"App.Operator": "operator"}
            assert sign_in_roles.role_from_claims({"roles": ["App.Boss"]}) is None
            assert sign_in_roles.role_from_claims({"roles": ["App.Admin"]}) is None  # role names are lower case
            assert sign_in_roles.role_from_claims({"roles": ["App.Boss", "App.Operator"]}) == "operator"
    warnings = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 2  # one for each bad entry, however often the settings are read
    assert any("App.Boss" in line and "superuser" in line for line in warnings)
    assert any("App.Admin" in line for line in warnings)


@pytest.mark.parametrize("body", [
    '[auth.oidc]\nrole_map = "admin"\n',
    '[auth.oidc]\nrole_map = ["SecondShift.Admin", "admin"]\n',
    '[auth.oidc]\nrole_map = true\n',
    '[auth.oidc.role_map]\n"SecondShift.Admin" = "admin"\n"SecondShift.Level" = 4\n',
    '[auth.oidc.role_map]\n"SecondShift.Admin" = "admin"\n"SecondShift.Many" = ["admin"]\n',
    '[auth.oidc.role_map]\n"SecondShift.Admin" = "admin"\n"SecondShift.Nested" = { role = "admin" }\n',
    '[auth.oidc.role_map]\n"SecondShift.Admin" = "admin"\n"" = "admin"\n',
    '[auth.oidc.role_map]\n"SecondShift.Admin" = "admin"\n"SecondShift.On" = true\n',
    '[auth.oidc]\nrole_claim = 5\n' + ROLE_MAP,
    '[auth.oidc]\nrole_claim = ""\n' + ROLE_MAP,
    '[auth.oidc]\nrole_claim = ["roles"]\n' + ROLE_MAP,
])
def test_a_malformed_setting_grants_nothing_and_says_so_once(installation, caplog, body):
    from maverick_dashboard import sign_in_roles

    _configure(installation, body)
    with caplog.at_level(logging.WARNING, logger="maverick_dashboard.sign_in_roles"):
        for _ in range(3):
            assert dict(sign_in_roles.load_settings().role_map) == {}
            # Not even the entry that was written correctly.
            assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Admin"]}) is None
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "ignored" in warnings[0].getMessage()


def test_settings_that_cannot_be_read_grant_nothing(installation):
    from maverick_dashboard import sign_in_roles

    _configure(installation, ROLE_MAP + "\nthis is not toml [[[\n")
    assert dict(sign_in_roles.load_settings().role_map) == {}
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Admin"]}) is None


def test_one_unreadable_settings_file_turns_the_whole_map_off(mapped):
    """Settings saved in the dashboard are layered over config.toml. If that
    layer cannot be read, a stricter entry in it may be lost: grant nothing."""
    from maverick import config
    from maverick_dashboard import sign_in_roles

    layer = config.dashboard_overrides_path()
    layer.parent.mkdir(parents=True, exist_ok=True)
    layer.write_text('[auth.oidc.role_map]\n"SecondShift.Admin" = "viewer"\n', encoding="utf-8")
    layer.chmod(0o600)
    config.reset_config_cache()
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Admin"]}) == "viewer"  # the stricter entry wins
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Operator"]}) == "operator"

    layer.write_text('[auth.oidc.role_map\n"SecondShift.Admin" = ', encoding="utf-8")
    config.reset_config_cache()
    assert dict(sign_in_roles.load_settings().role_map) == {}
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Admin"]}) is None
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Operator"]}) is None


def test_a_map_may_name_a_custom_role(installation):
    from maverick_dashboard import rbac, sign_in_roles

    path = rbac.custom_roles_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"privacy-officer": {"permissions": ["audit", "view"], "description": ""}}', encoding="utf-8")
    path.chmod(0o600)
    _configure(installation, '[auth.oidc.role_map]\n"App.Privacy" = "privacy-officer"\n')
    assert sign_in_roles.role_from_claims({"roles": ["App.Privacy"]}) == "privacy-officer"
    path.unlink()  # the custom role is deleted: the entry now names a role that does not exist
    assert sign_in_roles.role_from_claims({"roles": ["App.Privacy"]}) is None


# ------------------------------------------------------- several values

@pytest.mark.parametrize("values,winner", [
    (["SecondShift.Viewer", "SecondShift.Operator"], "operator"),
    (["SecondShift.Operator", "SecondShift.Viewer"], "operator"),          # order in the token does not matter
    (["SecondShift.Auditor", "SecondShift.GovernanceLead", "SecondShift.Operator"], "governance_lead"),
    (["SecondShift.Viewer", "SecondShift.Admin", "SecondShift.GovernanceLead"], "admin"),
    # A tie on the number of permissions (operate+view against audit+view) goes
    # to the role listed first among the built-in roles.
    (["SecondShift.Auditor", "SecondShift.Operator"], "operator"),
    (["SecondShift.Operator", "SecondShift.Auditor"], "operator"),
    (["Unmapped", "SecondShift.Viewer", "SecondShift.Viewer"], "viewer"),
])
def test_several_values_pick_the_role_with_the_most_permissions(mapped, values, winner):
    from maverick_dashboard import sign_in_roles

    assert sign_in_roles.role_from_claims({"roles": values}) == winner


def test_ties_between_custom_roles_go_to_built_in_roles_first_then_by_name(installation):
    from maverick_dashboard import rbac, sign_in_roles

    path = rbac.custom_roles_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '{"zeta-desk": {"permissions": ["operate", "view"], "description": ""},'
        ' "alpha-desk": {"permissions": ["audit", "view"], "description": ""},'
        ' "wide-desk": {"permissions": ["audit", "operate", "view"], "description": ""}}', encoding="utf-8")
    path.chmod(0o600)
    assert sign_in_roles.strongest(["zeta-desk", "alpha-desk"]) == "alpha-desk"    # same size: by name
    assert sign_in_roles.strongest(["alpha-desk", "zeta-desk"]) == "alpha-desk"
    assert sign_in_roles.strongest(["alpha-desk", "auditor"]) == "auditor"          # same size: built-in first
    assert sign_in_roles.strongest(["wide-desk", "governance_lead"]) == "governance_lead"
    assert sign_in_roles.strongest(["operator", "wide-desk"]) == "wide-desk"        # more permissions wins
    assert sign_in_roles.strongest([]) is None


def test_only_a_bounded_number_and_length_of_values_is_looked_at(mapped):
    from maverick_dashboard import sign_in_roles

    limit = sign_in_roles.MAX_CLAIM_VALUES
    filler = [f"Other.{index}" for index in range(limit)]
    assert sign_in_roles.role_from_claims({"roles": filler[:-1] + ["SecondShift.Admin"]}) == "admin"
    assert sign_in_roles.role_from_claims({"roles": filler + ["SecondShift.Admin"]}) is None


def test_a_value_longer_than_the_limit_is_not_looked_at(installation):
    from maverick_dashboard import sign_in_roles

    longest, too_long = "L" * sign_in_roles.MAX_VALUE_LENGTH, "L" * (sign_in_roles.MAX_VALUE_LENGTH + 1)
    _configure(installation, f'[auth.oidc.role_map]\n"{longest}" = "operator"\n"{too_long}" = "admin"\n')
    assert sign_in_roles.role_from_claims({"roles": [longest]}) == "operator"
    assert sign_in_roles.role_from_claims({"roles": [too_long]}) is None  # even though the map names it
    assert sign_in_roles.role_from_claims({"roles": too_long}) is None
    assert sign_in_roles.role_from_claims({"roles": [too_long, longest]}) == "operator"


# ------------------------------------------------------- browser sign-in

def test_sign_in_maps_the_app_role_into_the_signed_session(mapped, client, monkeypatch, token):
    session = _sign_in(client, monkeypatch, token, roles=["SecondShift.Operator"])
    assert session["sub"] == "alice" and session["oidc_role_values"] == {"name": "roles", "values": ["SecondShift.Operator"]}
    assert _may(client) == {"view", "operate"}


def test_a_governance_lead_operates_and_reads_the_audit_record_without_administrator_rights(
        mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.GovernanceLead"])
    assert _may(client) == {"view", "operate", "audit"}


def test_an_administrator_app_role_gives_administrator_rights(mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin"])
    assert _may(client) == {"view", "operate", "audit", "admin"}


def test_no_claim_falls_back_to_the_default_role(mapped, client, monkeypatch, token):
    session = _sign_in(client, monkeypatch, token)
    assert "claim_role" not in session
    assert _may(client) == {"view"}  # the default role is viewer

    _configure(mapped, '[dashboard]\ndefault_role = "operator"\n' + ROLE_MAP)
    assert _may(client) == {"view", "operate"}


def test_an_unmapped_value_falls_back_to_the_default_role(mapped, client, monkeypatch, token):
    session = _sign_in(client, monkeypatch, token, roles=["Payroll.Admin", "admin"])
    assert "claim_role" not in session
    assert _may(client) == {"view"}


def test_with_no_map_sign_in_is_exactly_as_before(installation, client, monkeypatch, token):
    session = _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin", "admin"])
    assert set(session) == {"sub", "iat", "exp", "sid", "mfa", "oidc_issuer", "oidc_audience",
                            "idp_email", "verified_email"}
    assert _may(client) == {"view"}


def test_a_malformed_map_grants_nothing_at_sign_in(installation, client, monkeypatch, token):
    _configure(installation, '[auth.oidc.role_map]\n"SecondShift.Admin" = "admin"\n"SecondShift.Level" = 4\n')
    session = _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin"])
    assert "claim_role" not in session
    assert _may(client) == {"view"}


def test_a_token_the_provider_did_not_sign_grants_nothing(mapped, client, monkeypatch, token):
    def forged(sub, **claims):
        return token(sub, key=1, **claims)

    assert _sign_in(client, monkeypatch, forged, roles=["SecondShift.Admin"]) is None
    assert client.get(f"{BASE}/status").status_code == 401


def test_a_stored_role_beats_the_claim(mapped, client, monkeypatch, token):
    _store_role("user:alice", "viewer")
    session = _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin"])
    assert session["oidc_role_values"]["values"] == ["SecondShift.Admin"]  # stored role still decides
    assert _may(client) == {"view"}

    _store_role("user:alice", "operator")
    assert _may(client) == {"view", "operate"}


def test_an_administrator_named_in_settings_beats_the_stored_role_and_the_claim(mapped, client, monkeypatch, token):
    _store_role("user:alice", "viewer")
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Viewer"])
    assert _may(client) == {"view"}
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    assert _may(client) == {"view", "operate", "audit", "admin"}


def test_a_second_sign_in_without_the_app_role_loses_it(mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin"])
    assert _may(client) == {"view", "operate", "audit", "admin"}

    # The app role was removed at the identity provider; the person signs in again.
    session = _sign_in(client, monkeypatch, token)
    assert "claim_role" not in session
    assert _may(client) == {"view"}


def test_a_role_taken_out_of_the_map_stops_applying_to_open_sessions(mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin"])
    assert "admin" in _may(client)
    _configure(mapped, '[auth.oidc.role_map]\n"SecondShift.Operator" = "operator"\n')
    assert _may(client) == {"view"}
    _configure(mapped, "")  # the whole map removed
    assert _may(client) == {"view"}
    _configure(mapped, '[auth.oidc]\nrole_map = "admin"\n')  # or left malformed
    assert _may(client) == {"view"}


def test_the_refusal_names_the_role_and_where_it_came_from(mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Operator"])
    refusal = client.post(f"{BASE}/timeboxes/sweep")
    assert refusal.status_code == 403
    assert "Your Operator role from verified sign-in app role does not allow admin" in refusal.json()["detail"]


def test_sign_in_writes_no_token_and_no_claim_value_to_the_log(mapped, client, monkeypatch, token, caplog):
    minted: list[str] = []

    def remembering(sub, **claims):
        minted.append(token(sub, **claims))
        return minted[-1]

    with caplog.at_level(logging.DEBUG):
        _sign_in(client, monkeypatch, remembering, roles=["Payroll.Secret-Marker", "SecondShift.Operator"])
        _may(client)
    assert minted and minted[0] not in caplog.text
    assert "Payroll.Secret-Marker" not in caplog.text
    assert SESSION_SECRET not in caplog.text


def test_per_person_isolation_carries_the_claim_role_on_the_unchanged_path(mapped, client, monkeypatch, token):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "_tenant_pin_choice", _UNCHANGED["tenant_pin_choice"])  # no stand-in here
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    _sign_in(client, monkeypatch, token, roles=["SecondShift.GovernanceLead"])
    assert client.get(f"{BASE}/status").status_code == 200
    assert client.get(f"{BASE}/timeboxes").status_code == 200
    assert client.post(f"{BASE}/timeboxes/sweep").status_code == 403


# ------------------------------------------------------- bearer tokens

def test_a_bearer_token_carries_its_own_app_role(mapped, client, token):
    def bearer(**claims):
        return TestClient(client.app, base_url="http://127.0.0.1", headers={
            "Origin": "http://127.0.0.1", "Authorization": "Bearer " + token("svc-reporting", **claims)})

    assert _may(bearer(roles=["SecondShift.GovernanceLead"])) == {"view", "operate", "audit"}
    assert _may(bearer(roles="SecondShift.Auditor")) == {"view", "audit"}
    assert _may(bearer()) == {"view"}                        # no claim: the default role
    assert _may(bearer(roles=["Payroll.Admin"])) == {"view"}  # not in the map


def test_a_bearer_token_follows_the_same_order(mapped, token, monkeypatch):
    from maverick_dashboard import auth

    request = _request(bearer=token("bob", roles=["SecondShift.Operator"]))
    assert auth.caller_role(request) == "operator"
    _store_role("user:bob", "auditor")
    assert auth.caller_role(request) == "auditor"
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:bob")
    assert auth.caller_role(request) == "admin"


def test_a_bearer_token_with_a_bad_signature_is_refused(mapped, token):
    with pytest.raises(HTTPException) as refused:
        _request(bearer=token("bob", key=1, roles=["SecondShift.Admin"]))
    assert refused.value.status_code == 401


def test_a_websocket_bearer_carries_its_own_app_role(mapped, token):
    from maverick_dashboard import auth

    connection = _request(bearer=token("bob", roles=["SecondShift.Auditor"]), websocket=True)
    assert auth.caller_role(connection) == "auditor"


def test_a_claim_named_like_the_session_field_is_not_a_role(mapped, client, monkeypatch, token):
    """Only the two places that verify a token may attach a role; a token cannot
    name its own by carrying the field the session uses."""
    from maverick_dashboard import auth

    request = _request(bearer=token("mallory", claim_role="admin", via="session", roles=["Payroll.Admin"]))
    assert auth.caller_role(request) == "viewer"
    assert auth.has_permission(request, "admin") is False

    session = _sign_in(client, monkeypatch, token, sub="mallory", claim_role="admin")
    assert "claim_role" not in session
    assert _may(client) == {"view"}


def test_with_no_map_a_bearer_identity_is_the_object_verification_returned(installation, token, monkeypatch):
    from maverick.oidc import verify_oidc_token
    from maverick_dashboard import auth

    verified = verify_oidc_token(token("bob", roles=["SecondShift.Admin"]))
    monkeypatch.setattr(auth, "verify_oidc_token", lambda _token: verified)
    request = _request(bearer="anything")
    assert request.state.principal is verified
    assert auth.caller_role(request) == "viewer"


# ------------------------------------------- whose role, and where it applies

def test_one_persons_claim_role_is_never_applied_to_another_principal(mapped, client, monkeypatch, token):
    from maverick_dashboard import auth, rbac, sign_in_roles

    _sign_in(client, monkeypatch, token, sub="alice", roles=["SecondShift.Admin"])
    alice = _request(session=client.cookies.get("ss_session"))
    assert auth.caller_principal(alice) == "user:alice"
    assert auth.role_for_principal("user:alice", request=alice) == "admin"

    # Asked about someone else through Alice's request: only what is stored or default.
    for other in ("user:bob", "user:alice ", "user:ALICE", "alice", "user:alice2", ""):
        assert sign_in_roles.for_request(alice, other) is None
        assert auth.role_for_principal(other, request=alice) in ("viewer", None)
        assert auth.global_role_for_principal(other, request=alice) in ("viewer", None)
    assert auth.role_for_principal(None, request=alice) is None

    # Bob's own request sees Bob's role, never Alice's.
    bob = _request(bearer=token("bob"))
    assert auth.caller_role(bob) == "viewer"
    assert auth.role_for_principal("user:alice", request=bob) == "viewer"
    assert "admin" not in rbac.permissions_for(auth.global_role_for_principal("user:alice", request=bob))


def test_another_persons_role_check_never_reads_the_callers_claim(mapped, token):
    """A check about a named reviewer (content_access) passes only the reviewer's
    name: a caller who is an administrator by claim does not make them one."""
    from maverick_dashboard import auth, content_access

    alice = _request(bearer=token("alice", roles=["SecondShift.Admin"]))
    assert auth.has_global_permission(alice, "admin") is True
    grant = {"reviewed_by": "user:alice", "requester": "user:carol", "owner": "user:dave"}
    assert content_access._reviewer_current(grant) is False


def test_background_lookups_with_no_request_get_no_claim_role(mapped, client, monkeypatch, token):
    from maverick_dashboard import auth, sign_in_roles

    _sign_in(client, monkeypatch, token, sub="alice", roles=["SecondShift.Admin"])
    alice = _request(session=client.cookies.get("ss_session"))
    assert auth.caller_role(alice) == "admin"

    # No request: the same person resolves to the default role.
    assert sign_in_roles.for_request(None, "user:alice") is None
    assert auth.role_for_principal("user:alice") == "viewer"
    assert auth.global_role_for_principal("user:alice") == "viewer"
    # Nothing is left in the surrounding context for later work to pick up.
    assert contextvars.copy_context().run(auth.role_for_principal, "user:alice") == "viewer"
    # A stand-in that has no verified caller on it is not a request either.
    assert sign_in_roles.for_request(SimpleNamespace(), "user:alice") is None
    assert sign_in_roles.for_request(SimpleNamespace(state=SimpleNamespace(principal=None)), "user:alice") is None


def test_only_a_role_attached_by_verification_counts(mapped):
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import auth, sign_in_roles

    def carrying(value, **claims):
        principal = VerifiedPrincipal("alice", "oidc-session", "", {"via": "session", "claim_role": value, **claims})
        return SimpleNamespace(state=SimpleNamespace(principal=principal))

    assert sign_in_roles.for_request(carrying(sign_in_roles.ClaimRole("operator")), "user:alice") == "operator"
    assert auth.role_for_principal("user:alice", request=carrying(sign_in_roles.ClaimRole("operator"))) == "operator"
    for value in ("operator", "admin", ["admin"], True, None, {"role": "admin"}):
        assert sign_in_roles.for_request(carrying(value), "user:alice") is None
    # Attached, but naming a role the current map does not give or that does not exist.
    assert sign_in_roles.for_request(carrying(sign_in_roles.ClaimRole("superuser")), "user:alice") is None
    assert sign_in_roles.for_request(carrying(sign_in_roles.ClaimRole("")), "user:alice") is None


def test_only_a_provider_sign_in_session_carries_the_role():
    from maverick_dashboard import oidc_login, sign_in_roles

    now = time.time()
    payload = {"sub": "alice", "iat": now, "oidc_role_values": {"name": "roles", "values": ["SecondShift.Operator"]}}
    signed_in = oidc_login.session_claims(payload, None, via="session")
    assert signed_in["claim_role"] == sign_in_roles.SessionRoleClaims("roles", ("SecondShift.Operator",))
    invited = oidc_login.session_claims(payload, None, via="invite")
    assert "claim_role" not in invited
    old = oidc_login.session_claims({"sub": "alice", "iat": now, "claim_role": "operator"}, None, via="session")
    assert "claim_role" not in old


def test_the_explanation_follows_the_same_order(mapped, token, monkeypatch):
    from maverick_dashboard import access_explanations

    request = _request(bearer=token("alice", roles=["SecondShift.Operator"]))
    explained = access_explanations.role("user:alice", request=request)
    assert explained["role"] == "operator" and explained["source"] == "Verified sign-in app role"
    assert access_explanations.role("user:alice")["source"] == "Configured first-login default"
    assert access_explanations.role("user:bob", request=request)["role"] == "viewer"
    _store_role("user:alice", "auditor")
    assert access_explanations.role("user:alice", request=request)["source"] == "Explicit installation role"
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    assert access_explanations.role("user:alice", request=request)["role"] == "admin"


# ------------------------------------------------- where it sits in the order

def _carrying(sub: str, role: str | None):
    """A request whose verified caller is ``sub`` and carries ``role`` from sign-in."""
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import sign_in_roles

    claims = {"via": "session"}
    if role is not None:
        claims["claim_role"] = sign_in_roles.ClaimRole(role)
    return SimpleNamespace(state=SimpleNamespace(principal=VerifiedPrincipal(sub, "oidc-session", "", claims)),
                           headers={}, cookies={})


def test_a_role_stored_for_the_active_workspace_beats_the_claim(mapped):
    from maverick import paths
    from maverick_dashboard import auth, rbac

    roster = rbac.tenant_store_path()
    roster.parent.mkdir(parents=True, exist_ok=True)
    roster.write_text('{"acme": {"user:alice": "viewer"}}', encoding="utf-8")
    roster.chmod(0o600)
    token = paths.set_tenant("acme")
    try:
        assert auth.role_for_principal("user:alice", request=_carrying("alice", "admin")) == "viewer"
        # No membership there: the claim role is an assignment of its own ...
        assert auth.role_for_principal("user:bob", request=_carrying("bob", "operator")) == "operator"
        # ... while someone with neither still gets no role once workspace lists are in use.
        assert auth.role_for_principal("user:carol", request=_carrying("carol", None)) is None
        assert auth.role_for_principal("user:bob") is None
    finally:
        paths.reset_tenant(token)


def test_installation_wide_pages_see_the_claim_role_of_their_own_caller(mapped):
    from maverick_dashboard import app as app_module
    from maverick_dashboard import auth

    lead = _carrying("alice", "governance_lead")
    assert app_module._page_role(lead) == "governance_lead"
    assert app_module._page_role(lead, global_scope=True) == "governance_lead"
    assert auth.has_global_permission(lead, "audit") is True
    assert auth.has_global_permission(lead, "admin") is False
    assert app_module._page_role(_carrying("alice", None), global_scope=True) == "viewer"


def test_a_role_check_inside_a_page_render_reads_settings_saved_during_it(installation):
    """A page render shares one read of the settings; a role check inside it
    must still see what was saved meanwhile (the default role and the map)."""
    from maverick import config
    from maverick_dashboard import auth

    def save(body: str) -> None:
        replacement = installation / "config.toml.new"
        replacement.write_text(body, encoding="utf-8")
        os.replace(replacement, installation / "config.toml")

    _configure(installation, '[dashboard]\ndefault_role = "admin"\n' + ROLE_MAP)
    plain, lead = _carrying("alice", None), _carrying("bob", "governance_lead")
    with config.single_read():  # what rendering a page opens
        assert config.load_config()["dashboard"]["default_role"] == "admin"  # the render's own read
        assert auth.has_permission(plain, "admin") is True
        assert auth.caller_role(lead) == "governance_lead"
        save('[dashboard]\ndefault_role = "viewer"\n[auth.oidc.role_map]\n"SecondShift.Operator" = "operator"\n')
        assert auth.has_permission(plain, "admin") is False
        assert auth.has_global_permission(plain, "admin") is False
        assert auth.caller_role(plain) == "viewer"
        assert auth.caller_role(lead) == "viewer"  # no entry gives that role any more
        assert auth.has_global_permission(lead, "audit") is False


def test_settings_that_stop_being_readable_stop_the_claim_role(mapped):
    from maverick_dashboard import auth, sign_in_roles

    request = _carrying("alice", "admin")
    assert auth.caller_role(request) == "admin"
    _configure(mapped, ROLE_MAP + "\nthis is not toml [[[\n")
    assert sign_in_roles.for_request(request, "user:alice") is None
    assert auth.caller_role(request) is None  # no role at all while the settings cannot be read
    assert auth.has_permission(request, "view") is False


def test_a_session_cookie_signed_with_another_secret_is_not_a_session(mapped, client):
    from maverick.web_session import sign_session

    now = int(time.time())
    forged = sign_session({"sub": "mallory", "iat": now, "exp": now + 600, "claim_role": "admin"}, "not-the-secret")
    client.cookies.set("ss_session", forged)
    assert client.get(f"{BASE}/status").status_code == 401


def test_signing_in_again_with_another_app_role_replaces_the_role(mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Auditor"])
    assert _may(client) == {"view", "audit"}
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Operator"])
    assert _may(client) == {"view", "operate"}


def test_a_caller_without_a_claim_role_is_looked_up_by_principal_alone(mapped, monkeypatch):
    """The role lookups keep their one-argument form for everyone whose sign-in
    carries no claim role, so code that replaces them (as many tests do) with a
    function of the principal alone keeps working."""
    from maverick_dashboard import app as app_module
    from maverick_dashboard import auth

    asked: list[tuple] = []

    def lookup(*args, **kwargs):
        asked.append((args, kwargs))
        return "auditor"

    monkeypatch.setattr(auth, "role_for_principal", lookup)
    monkeypatch.setattr(auth, "global_role_for_principal", lookup)
    plain = _carrying("alice", None)
    assert auth.caller_role(plain) == "auditor"
    assert auth.has_permission(plain, "audit") is True
    assert auth.has_global_permission(plain, "operate") is False
    assert app_module._page_role(plain, global_scope=True) == "auditor"
    assert asked == [(("user:alice",), {})] * 4

    # Someone whose sign-in does carry one: the lookup is handed their own request.
    asked.clear()
    lead = _carrying("bob", "governance_lead")
    assert auth.caller_role(lead) == "auditor"
    assert asked == [(("user:bob",), {"request": lead})]


def test_original_role_mapping_changes_apply_to_the_current_session(mapped, client, monkeypatch, token):
    _sign_in(client, monkeypatch, token, roles=["SecondShift.Admin"])
    assert "admin" in _may(client)
    _configure(mapped, '[auth.oidc.role_map]\n"SecondShift.Other" = "admin"\n"SecondShift.Admin" = "operator"\n')
    assert _may(client) == {"view", "operate"}
