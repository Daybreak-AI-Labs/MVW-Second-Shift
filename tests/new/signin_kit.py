"""Shared set-up for the Home and Audit page tests: sign-in on, one person per role.

Each person signs in with a token minted here and checked by the real
``maverick.oidc.verify_oidc_token`` against a stand-in key endpoint, so every
answer comes from the real routes of the web app. A person is named after the
role stored for them (``auditor`` holds the ``auditor`` role).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

jwt = pytest.importorskip("jwt", reason="sign-in needs PyJWT")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

ISSUER = "https://login.example.test/contoso/v2.0"
AUDIENCE = "app-client-id"
SESSION_SECRET = "unit-test-session-secret"  # pragma: allowlist secret
ROLES = ("admin", "governance_lead", "operator", "approver", "responder", "auditor", "viewer")


def new_key():
    """The identity provider's key pair."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_private(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def configure(tmp_path, body: str) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


def start(tmp_path, monkeypatch, request, signing_key):
    """Turn sign-in on with its own files; returns the function that puts everything back."""
    from maverick import _oidc_jwks, config, killswitch, revocation, world_model
    from maverick.audit import signing
    from maverick_dashboard import oidc_login, rbac, sign_in_roles

    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"page-test:{request.node.nodeid}".encode()
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
        "MAVERICK_CONTROL_PLANE": "1", "MAVERICK_EXTERNAL_AGENTS": "1",
        "MAVERICK_HALT_FILE": str(tmp_path / "HALT"),
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_MFA_REQUIRE",
                 "MAVERICK_SEPARATE_APPROVER", "MAVERICK_ALERTS", "TEAMS_NOTIFY_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    # Each test has its own audit folder: the writer the app records to, and the
    # one the audit page reads, are this one.
    from maverick.audit import writer

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(writer, "_default", writer.AuditLog(tmp_path / "audit", sign=True))
    monkeypatch.setattr(writer, "_defaults", {})

    class KeyEndpoint:
        """The provider's published signing key, without the network."""

        def __init__(self, uri, **kwargs):
            pass

        def get_signing_keys(self, *, refresh):
            return [SimpleNamespace(key_id="k1", key=signing_key.public_key())]

    monkeypatch.setattr(jwt, "PyJWKClient", KeyEndpoint)

    def forget():
        _oidc_jwks._resolvers.clear()
        oidc_login._CONSUMED_TX_IDS.clear()
        sign_in_roles._WARNED.clear()
        config.reset_config_cache()
        revocation.reset_shared()
        killswitch._last_file_check_ts = 0.0
        killswitch._last_file_present = False

    forget()
    _write_private(rbac.store_path(), json.dumps({f"user:{role}": role for role in ROLES}))

    def stop():
        try:
            killswitch.clear()
        except Exception:  # noqa: BLE001 -- the emergency stop file lives in this test's own folder
            pass
        signing._reset_injected_keypair_cache()
        forget()

    return stop


def mint(signing_key, sub: str, **claims) -> str:
    now = int(time.time())
    body = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 600, **claims}
    return jwt.encode(body, signing_key, algorithm="RS256", headers={"kid": "k1"})


def client_for(app, signing_key, person: str) -> TestClient:
    return TestClient(app, base_url="http://127.0.0.1", headers={
        "Origin": "http://127.0.0.1", "Authorization": "Bearer " + mint(signing_key, person)})
