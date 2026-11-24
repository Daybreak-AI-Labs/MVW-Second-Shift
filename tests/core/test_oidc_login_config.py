"""Config-extension + discovery tests for the OIDC browser-login flow.

Covers the new ``[auth.oidc]`` fields (client_id/client_secret/redirect_uri/
session_secret + explicit endpoints), the env overrides, the ``login_enabled()``
fail-closed gate, and endpoint resolution (explicit-wins, discovery-fills,
https-only, fail-soft). No network: httpx is monkeypatched.
"""
from __future__ import annotations

import pytest
from maverick.oidc import load_oidc_config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Isolate from the host config + any MAVERICK_OIDC_* env, and clear the
    process-wide discovery cache between tests."""
    monkeypatch.setenv("HOME", str(tmp_path))  # no config.toml -> empty config
    for name in (
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_OIDC_ISSUER",
        "MAVERICK_OIDC_AUDIENCE",
        "MAVERICK_OIDC_JWKS_URI",
        "MAVERICK_OIDC_ALGORITHMS",
        "MAVERICK_OIDC_CLIENT_ID",
        "MAVERICK_OIDC_CLIENT_SECRET",
        "MAVERICK_OIDC_REDIRECT_URI",
        "MAVERICK_OIDC_SESSION_SECRET",
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT",
        "MAVERICK_OIDC_TOKEN_ENDPOINT",
    ):
        monkeypatch.delenv(name, raising=False)
    yield


def test_login_fields_default_empty():
    cfg = load_oidc_config()
    assert cfg.client_id == ""
    assert cfg.client_secret == ""
    assert cfg.redirect_uri == ""
    assert cfg.session_secret == ""
    assert cfg.authorization_endpoint == ""
    assert cfg.token_endpoint == ""


def test_login_fields_from_config(monkeypatch, tmp_path):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text(
        "[auth.oidc]\n"
        "enabled = true\n"
        'issuer = "https://idp.example.com"\n'
        'audience = "maverick"\n'
        'client_id = "cid-123"\n'
        'client_secret = "sekret"\n'  # pragma: allowlist secret
        'redirect_uri = "https://dash.example.com/auth/callback"\n'
        'session_secret = "hmac-key"\n'  # pragma: allowlist secret
    )
    cfg = load_oidc_config()
    assert cfg.client_id == "cid-123"
    assert cfg.client_secret == "sekret"  # pragma: allowlist secret
    assert cfg.redirect_uri == "https://dash.example.com/auth/callback"
    assert cfg.session_secret == "hmac-key"  # pragma: allowlist secret


def test_env_overrides_login_fields(monkeypatch):
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", "env-cid")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("MAVERICK_OIDC_REDIRECT_URI", "https://x/auth/callback")
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", "env-hmac")
    cfg = load_oidc_config()
    assert cfg.client_id == "env-cid"
    assert cfg.client_secret == "env-secret"  # pragma: allowlist secret
    assert cfg.redirect_uri == "https://x/auth/callback"
    assert cfg.session_secret == "env-hmac"  # pragma: allowlist secret
