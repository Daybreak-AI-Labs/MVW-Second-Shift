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
