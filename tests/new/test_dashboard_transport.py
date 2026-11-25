"""Browser transport keeps the verified request context and security headers."""
from __future__ import annotations

import asyncio
import re

import httpx
import pytest
from fastapi import Request

from maverick import paths
from maverick_dashboard import auth


@pytest.mark.asyncio
async def test_browser_verification_and_workspace_selection_use_one_worker_dispatch(monkeypatch):
    from maverick.oidc import VerifiedPrincipal

    principal = VerifiedPrincipal("test-person", "https://issuer.example", "second-shift", {})
    dispatch = auth.run_in_threadpool
    event_loop = asyncio.get_running_loop()
    calls = []

    async def track(function, *args, **kwargs):
        calls.append(function)
        return await dispatch(function, *args, **kwargs)

    def resolve(*args, **kwargs):
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()
        return principal

    def choose(_request, verified):
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()
        assert verified is principal
        return "principal_isolation", "api:user:test-person"

    def check(_request, verified):
        assert verified is principal and paths.current_tenant_id() == "api:user:test-person"

    monkeypatch.setattr(auth, "run_in_threadpool", track)
    monkeypatch.setattr(auth, "_resolve_principal", resolve)
    monkeypatch.setattr(auth, "_tenant_pin_choice", choose)
    monkeypatch.setattr(auth, "_enforce_workspace_policies", check)
    request = Request({"type": "http", "path": "/", "method": "GET", "headers": []})
    try:
        assert await auth.require_principal_in_request_context(request=request) is principal
        assert paths.current_tenant_id() == "api:user:test-person"
        assert asyncio.get_running_loop() is event_loop
        assert len(calls) == 2
    finally:
        if hasattr(request.state, "tenant_pin_token"):
            paths.reset_tenant(request.state.tenant_pin_token)


@pytest.mark.asyncio
async def test_security_headers_cover_pages_and_middleware_refusals(monkeypatch):
    from maverick_dashboard.app import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        first = await client.get("/approvals")
        second = await client.get("/approvals")
        assert first.status_code == second.status_code == 200
        nonce = re.search(r"'nonce-([^']+)'", first.headers["content-security-policy"])[1]
        assert f'nonce="{nonce}"' in first.text
        assert f"'nonce-{nonce}'" not in second.headers["content-security-policy"]
        assert first.headers["cache-control"] == "private, no-store"
        assert first.headers["referrer-policy"] == "same-origin"
        assert "strict-transport-security" not in first.headers

        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "synthetic-operator-key")
        refused = await client.get("/", headers={"X-Forwarded-Proto": "https"})
        assert refused.status_code == 401
        assert refused.headers["x-frame-options"] == "DENY"
        assert "strict-transport-security" in refused.headers


@pytest.mark.asyncio
async def test_versioned_dashboard_scripts_cache_without_browser_authority(monkeypatch):
    from maverick_dashboard.app import app, static_version

    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "synthetic-operator-key")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        for name in ("second-shift.css", "second-shift-ui.js", "second-shift-approvals.js",
                     "second-shift-outside-agents.js"):
            path = f"/static/{name}"
            version = static_version(name)
            assert version
            bundle = await client.get(path, params={"v": version})
            assert bundle.status_code == 200
            assert bundle.headers["cache-control"] == "public, max-age=31536000, immutable"
            canonical = await client.get(path)
            assert canonical.headers["cache-control"] == "public, no-cache"
            unchanged = await client.get(path, headers={"If-None-Match": canonical.headers["etag"]})
            assert unchanged.status_code == 304 and not unchanged.content
        artwork = await client.get("/static/second-shift-glass.webp")
        assert artwork.status_code == 200 and artwork.headers["content-type"] == "image/webp"
        assert artwork.headers["cache-control"] == "public, max-age=3600"
        assert (await client.get("/static/second-shift-decisions.js")).status_code == 401
        assert (await client.get("/approvals")).status_code == 401
