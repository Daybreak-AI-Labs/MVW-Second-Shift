"""The sign-in timer's three reads and the page meta tags it depends on.

Sessions here are real signed cookies recorded in the session registry; only
the clock is moved. Sign-in is always the company's, so staying signed in
means signing in again, never a silent renewal.
"""
from __future__ import annotations

import re
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

SESSION_SECRET = "unit-test-session-secret"  # pragma: allowlist secret
ORIGIN = "http://127.0.0.1"


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name, value in {
        "MAVERICK_OIDC_ENABLED": "1", "MAVERICK_OIDC_ISSUER": "https://login.example.test/t/v2.0",
        "MAVERICK_OIDC_AUDIENCE": "app-client-id", "MAVERICK_OIDC_CLIENT_ID": "app-client-id",
        "MAVERICK_OIDC_CLIENT_SECRET": "test-client-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_JWKS_URI": "https://login.example.test/t/keys",
        "MAVERICK_OIDC_REDIRECT_URI": f"{ORIGIN}/auth/callback",
        "MAVERICK_OIDC_SESSION_SECRET": SESSION_SECRET,
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT": "https://login.example.test/t/authorize",
        "MAVERICK_OIDC_TOKEN_ENDPOINT": "https://login.example.test/t/token",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_PROXY_AUTH",
                 "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_MFA_REQUIRE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _configure(tmp_path, body: str) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


def _cookie(*, ttl: int = 3600, sub: str = "alice") -> str:
    from maverick_dashboard import oidc_login

    fake = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={"user-agent": "test"})
    return oidc_login.mint_browser_session(fake, sub=sub, secret=SESSION_SECRET, via="session",
                                           mfa=False, ttl=ttl)


@pytest.fixture
def client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}, follow_redirects=False)


def _signed_in(client, **kwargs):
    from maverick_dashboard import oidc_login

    client.cookies.set(oidc_login.SESSION_COOKIE, _cookie(**kwargs))
    return client


def _meta(page: str, name: str):
    found = re.search(r'<meta name="' + re.escape(name) + r'" content="([^"]*)">', page)
    return found.group(1) if found else None


def test_a_signed_in_page_says_when_sign_in_ends_and_where_to_sign_in_again(client):
    page = _signed_in(client, ttl=3600).get("/external-agents")
    assert page.status_code == 200
    assert abs(int(_meta(page.text, "second-shift-session-expires")) - (time.time() + 3600)) < 120
    assert abs(int(_meta(page.text, "second-shift-session-now")) - time.time()) < 120
    assert _meta(page.text, "second-shift-session-renew") == "sign-in"
    assert _meta(page.text, "second-shift-session-sign-in") == "/auth/login"
    assert "second-shift-session.js" in page.text
    script = client.get("/static/second-shift-session.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"]


def test_status_reports_the_end_the_clock_and_the_way_to_stay(client):
    answer = _signed_in(client, ttl=1800).get("/auth/session/status")
    assert answer.status_code == 200 and answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert body["signed_in"] is True and body["renew"] == "sign-in" and body["idle_minutes"] == 0
    assert abs(body["expires_at"] - (time.time() + 1800)) < 120
    assert abs(body["now"] - time.time()) < 120


def test_a_session_ended_on_the_sessions_page_shows_no_timer(client):
    from maverick.web_session import verify_session
    from maverick_dashboard import oidc_login, session_registry

    _signed_in(client)
    sid = verify_session(client.cookies.get(oidc_login.SESSION_COOKIE), SESSION_SECRET)["sid"]
    session_registry.revoke(sid, by="test")
    # The sign-in itself is refused once its record is ended.
    assert client.get("/auth/session/status").status_code == 401


def test_a_cookie_signed_with_another_secret_is_not_a_session(client):
    from maverick.web_session import sign_session
    from maverick_dashboard import oidc_login

    now = int(time.time())
    client.cookies.set(oidc_login.SESSION_COOKIE,
                       sign_session({"sub": "mallory", "iat": now, "exp": now + 600}, "not-the-secret"))
    assert client.get("/auth/session/status").status_code == 401


def test_an_idle_limit_is_reported_and_activity_extends_only_the_idle_deadline(client, installation):
    _configure(installation, "[auth.sessions]\nidle_minutes = 5\n")
    _signed_in(client, ttl=3600)
    status = client.get("/auth/session/status").json()
    assert status["idle_minutes"] == 5
    assert status["expires_at"] <= time.time() + 5 * 60 + 5
    activity = client.post("/auth/session/activity")
    assert activity.status_code == 200
    # The ceiling set at sign-in is never moved: the answer stays within it.
    assert activity.json()["expires_at"] <= time.time() + 5 * 60 + 5
    assert activity.json()["expires_at"] >= status["expires_at"]


def test_activity_and_renew_need_a_live_session_and_the_same_origin(client):
    assert client.post("/auth/session/activity").status_code == 401
    assert client.post("/auth/session/renew").status_code == 401
    _signed_in(client)
    for path in ("/auth/session/activity", "/auth/session/renew"):
        refused = client.post(path, headers={"Origin": "https://elsewhere.example"})
        assert refused.status_code == 403, path


def test_a_company_sign_in_cannot_be_renewed_in_place(client):
    answer = _signed_in(client).post("/auth/session/renew")
    assert answer.status_code == 409
    assert answer.json() == {"renew": "sign-in", "sign_in": "/auth/login"}
    assert "set-cookie" not in answer.headers


def test_no_sign_in_means_no_timer_script_and_no_new_cookie(client):
    from maverick_dashboard.session_expiry import page_session

    page = client.get("/external-agents")
    assert _meta(page.text, "second-shift-session-expires") is None
    assert "second-shift-session.js" not in page.text
    assert page_session(SimpleNamespace(cookies={})) is None


def test_the_timer_script_calls_only_the_three_session_addresses():
    from pathlib import Path

    import maverick_dashboard

    script = (Path(maverick_dashboard.__file__).parent / "static" / "second-shift-session.js").read_text(encoding="utf-8")
    assert sorted(set(re.findall(r"mvFetchJSON\('([^']+)'", script))) == [
        "/auth/session/activity", "/auth/session/renew", "/auth/session/status"]
