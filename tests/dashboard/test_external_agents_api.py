"""Bring-your-own-agent gateway over HTTP: admin enrollment + credential
minting on the dashboard surface, and the self-authenticated agent-facing
routes (minted bearer or platform-native credential — no session, no CSRF
surface, 404 while disabled)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import time

import pytest
from fastapi.testclient import TestClient

from maverick_dashboard.app import app

# Crypto availability gate for the signed-identity tests (same probe as
# test_oidc / test_external_identity): if this sandbox's cryptography/PyJWT
# is broken they SKIP — CI has working crypto and is the real gate.
_CRYPTO_OK = True
_CRYPTO_SKIP_REASON = ""
try:  # noqa: SIM105
    import jwt  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    _probe = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _probe.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
except Exception as _e:  # pragma: no cover - env-dependent
    _CRYPTO_OK = False
    _CRYPTO_SKIP_REASON = (
        f"working cryptography/PyJWT unavailable: {type(_e).__name__}: {_e}")

requires_crypto = pytest.mark.skipif(not _CRYPTO_OK,
                                     reason=_CRYPTO_SKIP_REASON)

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import agent_trust, config, external_agents, world_model
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(agent_trust, "managed_path",
                        lambda: tmp_path / "agent_trust.json")
    monkeypatch.setattr(external_agents, "registry_path",
                        lambda: tmp_path / "external_agents.json")
    # Unrated action names take the high refusal floor, so the deployment
    # rates this fixture's platform actions and fake connector read the way an
    # operator classifies their own (wire_transfer/send_contract stay high).
    (tmp_path / "config.toml").write_text(
        '[security.tool_risk]\nresearch = "low"\ncrm_update = "medium"\n"fakecrm.read" = "low"\n',
        encoding="utf-8")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_chunked_external_body_stops_reading_at_limit(monkeypatch):
    import httpx

    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    sent = []

    async def chunks():
        for i in range(3):
            sent.append(i)
            yield b"x" * (128 * 1024 + 1)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1") as requester:
            return await requester.post("/api/v1/external/runs", content=chunks())

    assert asyncio.run(run()).status_code == 413
    assert sent == [0, 1]


def test_signed_get_body_is_limited_before_authentication(monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    response = client.request(
        "GET", "/api/v1/external/approvals/1", content=b"{}",
        headers={"Content-Length": str(256 * 1024 + 1), "X-Agent-Signature": "synthetic"},
    )
    assert response.status_code == 413


def test_slow_external_body_times_out_and_releases_capacity(monkeypatch):
    import httpx

    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    monkeypatch.setattr(dash_app, "_EXTERNAL_BODY_SLOTS", 1)
    monkeypatch.setattr(dash_app, "_EXTERNAL_BODY_TIMEOUT_SECONDS", 0.03)

    async def slow():
        yield b"{"
        await asyncio.sleep(1)
        yield b"}"

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1") as requester:
            first = await requester.post("/api/v1/external/runs", content=slow())
            second = await requester.post("/api/v1/external/runs", content=b"{}")
            return first.status_code, second.status_code

    first, second = asyncio.run(run())
    assert first == 408
    assert second != 503


def _enroll(**overrides):
    body = {"id": "sf-quotebot", "platform": "agentforce",
            "description": "quoting agent", "owner": "jordan@corp.test",
            "department": "sales", "max_risk": "medium", "max_dollars": 5.0}
    body.update(overrides)
    return client.post("/api/v1/external-agents", json=body)


def _mint() -> str:
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "rest"})
    assert r.status_code == 200
    return r.json()["token"]


def test_enroll_mint_and_roster_roundtrip():
    r = _enroll()
    assert r.status_code == 201
    assert r.json()["trust"] == "registered"
    token = _mint()
    assert token.startswith("lw-rest-")
    listing = client.get("/api/v1/external-agents").json()
    (row,) = listing["agents"]
    assert row["platform_label"] == "Salesforce Agentforce"
    assert row["credentials"] == ["rest"]
    # The token value never reappears on any read surface.
    assert token not in str(listing)
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["department"] == "sales"
    assert client.get("/api/v1/external-agents/ghost").status_code == 404


def test_enroll_validates_platform_and_surface():
    assert _enroll(platform="skynet").status_code == 400
    _enroll()
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "carrier-pigeon"})
    assert r.status_code == 422


def test_agent_facing_routes_require_the_rest_bearer():
    _enroll()
    token = _mint()
    # No session, no Origin — the bearer alone authenticates (self-auth path).
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/runs",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"title": "Quote for Northwind", "outcome": "success",
                        "summary": "sent", "cost_dollars": 1.25})
    assert r.status_code == 201
    body = r.json()
    assert body["ok"] is True and body["over_budget"] is False
    # The run is on the Operating Record, visible from the admin detail.
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["runs"] == 1
    assert detail["record"]["dollars"] == pytest.approx(1.25)
    # Missing/garbage bearer -> 401, never a fallback to ambient auth.
    assert bare.post("/api/v1/external/runs", json={}).status_code == 401
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": "Bearer lw-rest-wrong"},
                  json={"tool": "crm_update"})
    assert r.status_code == 401


def test_screen_flow_and_approval_poll_over_http():
    _enroll(max_risk="high")
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    ok = bare.post("/api/v1/external/screen", headers=hdr,
                   json={"tool": "crm_update", "detail": "update stage",
                         "risk": "low"}).json()
    assert ok["allowed"] is True
    parked = bare.post("/api/v1/external/screen", headers=hdr,
                       json={"tool": "send_contract", "risk": "high"}).json()
    assert parked["requires_approval"] is True
    poll = bare.get(f"/api/v1/external/approvals/{parked['approval_id']}",
                    params={"binding_sha256": parked["approval_binding_sha256"]},
                    headers=hdr)
    assert poll.status_code == 200
    assert poll.json()["status"] == "pending"
    assert (
        poll.json()["approval_binding_sha256"]
        == parked["approval_binding_sha256"]
    )
    stale = bare.get(
        f"/api/v1/external/approvals/{parked['approval_id']}",
        params={"binding_sha256": "0" * 64},
        headers=hdr,
    )
    assert stale.status_code == 409
    assert bare.get("/api/v1/external/approvals/999999",
                    headers=hdr).status_code == 404

    assert _enroll(
        id="other-agent", owner="other@corp.test", max_risk="high"
    ).status_code == 201
    other_token = client.post(
        "/api/v1/external-agents/other-agent/credentials",
        json={"surface": "rest"},
    ).json()["token"]
    cross_owner = bare.get(
        f"/api/v1/external/approvals/{parked['approval_id']}",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert cross_owner.status_code == 404


def test_gateway_404s_while_disabled(monkeypatch):
    _enroll()
    token = _mint()
    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS", raising=False)
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"tool": "crm_update"})
    assert r.status_code == 404
    assert bare.get("/api/v1/external/openapi.json").status_code == 404
    page = client.get("/external-agents")
    assert page.status_code == 200
    assert 'href="/api/v1/external/openapi.json"' not in page.text
    assert "The connection file is available once the connection is open" in page.text


def test_console_page_renders_roster_and_forms():
    _enroll()
    page = client.get("/external-agents").text
    assert "Add an outside agent" in page
    assert 'id="xa-add"' in page
    assert "data-xa-mint" in page
    assert "Salesforce Agentforce" in page
    assert "Connect your platform" in page
    assert 'href="/api/v1/external/openapi.json"' in page


def test_admin_mutations_are_csrf_gated_but_gateway_is_not():
    # The ADMIN surface keeps the same-origin gate in no-token mode…
    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/api/v1/external-agents",
                     json={"id": "x", "platform": "custom"}).status_code == 403


def test_unenroll_over_http():
    _enroll()
    assert client.delete("/api/v1/external-agents/sf-quotebot").status_code == 204
    assert client.delete("/api/v1/external-agents/sf-quotebot").status_code == 404
    assert client.get("/api/v1/external-agents").json()["agents"] == []


def test_live_run_flow_over_http():
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    start = bare.post("/api/v1/external/runs/start", headers=hdr,
                      json={"title": "Live quote", "summary": "working"})
    assert start.status_code == 201
    gid = start.json()["goal_id"]
    assert start.json()["heartbeat_seconds"] > 0
    hb = bare.post(f"/api/v1/external/runs/{gid}/heartbeat", headers=hdr)
    assert hb.status_code == 200 and hb.json()["continue"] is True
    fin = bare.post(f"/api/v1/external/runs/{gid}/finish", headers=hdr,
                    json={"outcome": "success", "summary": "sent",
                          "cost_dollars": 1.5, "steps": ["a"]})
    assert fin.status_code == 200
    assert fin.json()["over_budget"] is False
    # Closed run: heartbeat says stop, finish refuses.
    hb = bare.post(f"/api/v1/external/runs/{gid}/heartbeat", headers=hdr)
    assert hb.json()["continue"] is False
    fin = bare.post(f"/api/v1/external/runs/{gid}/finish", headers=hdr,
                    json={"outcome": "success", "summary": "again"})
    assert fin.status_code == 403
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["record"]["dollars"] == pytest.approx(1.5)


def test_scorecard_page_renders_and_404s_unknown():
    _enroll()
    page = client.get("/external-agents/sf-quotebot")
    assert page.status_code == 200
    assert "Spend and budget" in page.text
    assert "Salesforce Agentforce" in page.text
    assert client.get("/external-agents/ghost").status_code == 404


def test_idempotency_key_over_http():
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    body = {"title": "Quote", "outcome": "success", "summary": "s",
            "cost_dollars": 1.0, "idempotency_key": "k-1"}
    first = bare.post("/api/v1/external/runs", headers=hdr, json=body).json()
    replay = bare.post("/api/v1/external/runs", headers=hdr, json=body).json()
    assert replay["goal_id"] == first["goal_id"]
    assert replay["duplicate"] is True
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["runs"] == 1


def test_gateway_rate_limit_trips_and_names_the_action(monkeypatch):
    from maverick_dashboard import external_gateway as gw
    _enroll()
    token = _mint()
    monkeypatch.setitem(gw._RATE_LIMITS, "screen", 3)
    monkeypatch.setattr(gw, "_rate_times", {})
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    body = {"tool": "research", "risk": "low"}
    for _ in range(3):
        assert bare.post("/api/v1/external/screen", headers=hdr,
                         json=body).status_code == 200
    r = bare.post("/api/v1/external/screen", headers=hdr, json=body)
    assert r.status_code == 429
    assert "screen" in r.json()["detail"]
    assert r.headers["Retry-After"] == "60"


def test_admin_release_and_reset_budget_routes():
    _enroll(max_risk="medium", max_dollars=1.0)
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    # Trip the containment via repeated ceiling breaches.
    for _ in range(5):
        bare.post("/api/v1/external/screen", headers=hdr,
                  json={"tool": "wire_transfer", "risk": "high"})
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "contained"
    r = client.post("/api/v1/external-agents/sf-quotebot/release", json={})
    assert r.status_code == 200
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "allow"
    # Over-budget -> reset restores service.
    bare.post("/api/v1/external/runs", headers=hdr,
              json={"title": "Big", "outcome": "success", "summary": "s",
                    "cost_dollars": 2.0})
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "budget"
    r = client.post("/api/v1/external-agents/sf-quotebot/reset-budget",
                    json={})
    assert r.status_code == 200
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "allow"
    assert client.post("/api/v1/external-agents/ghost/release",
                       json={}).status_code == 404


def test_ordinary_admin_restore_and_release_refuse_security_containment():
    from maverick import agent_trust
    from maverick import external_agents as xa
    from maverick.revocation import shared

    assert _enroll().status_code == 201
    contained = shared().revoke(
        "agent:sf-quotebot", reason="soc: incident", protected=True,
    )
    assert agent_trust.set_revoked("sf-quotebot", True)
    assert xa.contain("sf-quotebot", contained_by="soc")

    restored = client.post(
        "/api/v1/trust/agents/sf-quotebot/revoke",
        json={"revoked": False},
    )
    assert restored.status_code == 409
    assert "security-contained" in restored.json()["detail"]
    released = client.post(
        "/api/v1/external-agents/sf-quotebot/release", json={},
    )
    assert released.status_code == 409
    assert "security-contained" in released.json()["detail"]

    assert shared().revoked()["agent:sf-quotebot"] == contained
    assert agent_trust.load_registry()["sf-quotebot"].revoked is True
    assert xa.containment_state("sf-quotebot") is True


_ISSUER = "https://partner-idp.example.com"
_AUDIENCE = "lightwork-gateway"
_HMAC_REF = "XA_GATEWAY_TEST_SECRET"
_HMAC_SECRET = "gw-test-secret"  # pragma: allowlist secret
_SCREEN_BODY = b'{"tool": "crm_update", "risk": "low"}'


def _identity(**fields):
    """Attach platform-identity fields to the enrolled agent's trust entry
    (the same read-modify-write mint_token uses, so bearers survive)."""
    from maverick import external_agents as xa
    from maverick.agent_trust import lookup, put_agent
    entry = xa._entry_from_agent(lookup("sf-quotebot"))
    entry.update(fields)
    put_agent(entry)


def _ed25519_pair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return priv, pub_hex


def _envelope_headers(priv, body: bytes, *, nonce: str) -> dict:
    from maverick.external_identity import envelope_message
    ts = str(int(time.time()))
    sig = priv.sign(envelope_message("sf-quotebot", ts, nonce, body)).hex()
    return {"X-Second-Shift-Agent-Id": "sf-quotebot",
            "X-Maverick-Timestamp": ts,
            "X-Second-Shift-Nonce": nonce,
            "X-Second-Shift-Request-Signature": sig,
            "Content-Type": "application/json"}


@requires_crypto
def test_envelope_auth_over_http():
    _enroll()
    priv, pub_hex = _ed25519_pair()
    _identity(pubkey=pub_hex)
    r = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/screen",
        headers=_envelope_headers(priv, _SCREEN_BODY, nonce="n-1"),
        content=_SCREEN_BODY)
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


@requires_crypto
def test_envelope_replayed_nonce_is_401():
    _enroll()
    priv, pub_hex = _ed25519_pair()
    _identity(pubkey=pub_hex)
    hdr = _envelope_headers(priv, _SCREEN_BODY, nonce="n-replay")
    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/api/v1/external/screen", headers=hdr,
                     content=_SCREEN_BODY).status_code == 200
    # A byte-identical replay carries a valid signature; the single-use
    # nonce is what refuses it — with the same generic 401.
    r = bare.post("/api/v1/external/screen", headers=hdr,
                  content=_SCREEN_BODY)
    assert r.status_code == 401


def _hmac_headers(body: bytes, *, ts: str | None = None) -> dict:
    ts = ts or str(int(time.time()))
    mac = hmac_mod.new(_HMAC_SECRET.encode(), f"{ts}.".encode() + body,
                       hashlib.sha256)
    return {"X-Second-Shift-Agent-Id": "sf-quotebot",
            "X-Maverick-Timestamp": ts,
            "X-Maverick-Signature": "sha256=" + mac.hexdigest(),
            "Content-Type": "application/json"}


def test_hmac_auth_over_http(monkeypatch):
    monkeypatch.setenv(_HMAC_REF, _HMAC_SECRET)
    _enroll()
    _identity(hmac_secret_ref=_HMAC_REF)
    r = TestClient(app, base_url="http://127.0.0.1").post("/api/v1/external/screen",
                             headers=_hmac_headers(_SCREEN_BODY),
                             content=_SCREEN_BODY)
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


def test_hmac_stale_timestamp_is_401(monkeypatch):
    monkeypatch.setenv(_HMAC_REF, _HMAC_SECRET)
    _enroll()
    _identity(hmac_secret_ref=_HMAC_REF)
    hdr = _hmac_headers(_SCREEN_BODY, ts=str(int(time.time()) - 4000))
    r = TestClient(app, base_url="http://127.0.0.1").post("/api/v1/external/screen", headers=hdr,
                             content=_SCREEN_BODY)
    assert r.status_code == 401


def _jwt_setup(tmp_path) -> bytes:
    """Pin issuer/audience + a PEM key file on the enrolled agent; return
    the matching private key for minting tokens."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    _identity(jwt_issuer=_ISSUER, jwt_audience=_AUDIENCE,
              jwks_file=str(key_file))
    return priv_pem


def _jwt_token(priv_pem: bytes, **overrides) -> str:
    now = int(time.time())
    claims = {"sub": "sf-quotebot", "iss": _ISSUER, "aud": _AUDIENCE,
              "iat": now, "exp": now + 600}
    claims.update(overrides)
    return jwt.encode(claims, priv_pem, algorithm="RS256")


@requires_crypto
def test_jwt_auth_over_http(tmp_path):
    _enroll()
    priv_pem = _jwt_setup(tmp_path)
    r = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/screen",
        headers={"Authorization": f"Bearer {_jwt_token(priv_pem)}"},
        json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


@requires_crypto
def test_jwt_for_another_subject_is_401(tmp_path):
    """A validly-signed token whose sub names another agent never
    authenticates this one."""
    _enroll()
    priv_pem = _jwt_setup(tmp_path)
    token = _jwt_token(priv_pem, sub="other-bot")
    r = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/screen",
        headers={"Authorization": f"Bearer {token}"},
        json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 401


def test_bearer_still_works_alongside_strong_credentials():
    """require_signed defaults OFF: enrolling a pubkey does not strand an
    agent still calling with its minted bearer."""
    _enroll()
    token = _mint()
    _identity(pubkey="ab" * 32)
    r = TestClient(app, base_url="http://127.0.0.1").post("/api/v1/external/screen",
                             headers={"Authorization": f"Bearer {token}"},
                             json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


def test_require_signed_refuses_bearer_for_strong_credential_agents(tmp_path):
    from maverick import config
    _enroll()
    token = _mint()
    _identity(pubkey="ab" * 32)
    _enroll(id="langbot", platform="custom")
    r = client.post("/api/v1/external-agents/langbot/credentials",
                    json={"surface": "rest"})
    plain_token = r.json()["token"]
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nrequire_signed = true\n", encoding="utf-8")
    config.reset_config_cache()
    bare = TestClient(app, base_url="http://127.0.0.1")
    body = {"tool": "crm_update", "risk": "low"}
    # The pubkey-bearing agent must present its strong credential…
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {token}"}, json=body)
    assert r.status_code == 401
    # …while a token-only agent keeps working.
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {plain_token}"},
                  json=body)
    assert r.status_code == 200, r.text


def test_require_signed_covers_hmac_only_agents(tmp_path):
    """An agent whose only strong credential is HMAC must also lose its
    bearer under require_signed — otherwise a leaked bearer keeps working
    against the very switch that was meant to retire it."""
    from maverick import config
    _enroll()
    token = _mint()
    _identity(hmac_secret_ref="SF_QUOTEBOT_HMAC")  # pragma: allowlist secret
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nrequire_signed = true\n", encoding="utf-8")
    config.reset_config_cache()
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 401
