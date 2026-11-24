"""Off-loop verification never moves the authoritative request tenant pin."""
from __future__ import annotations

import asyncio
import threading
import time
import pytest
from fastapi import HTTPException, Request, WebSocket
from maverick import paths
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import auth


@pytest.fixture
def identity(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    principal = VerifiedPrincipal("alice", "https://issuer.example", "lightwork", {"iat": time.time()})
    monkeypatch.setattr(auth, "verify_oidc_token", lambda _token: principal)
    return principal


def _connection(websocket=False):
    scope = {"type": "websocket" if websocket else "http", "path": "/metrics", "scheme": "http",
             "headers": [(b"authorization", b"Bearer synthetic"), (b"host", b"127.0.0.1")],
             "query_string": b"", "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1234)}
    return WebSocket(scope, receive=None, send=None) if websocket else Request(scope)


def test_cancelled_request_keeps_resolver_admission_until_worker_exits(identity, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(auth, "_OIDC_VERIFY_SLOTS", 1)
    monkeypatch.setattr(auth, "_OIDC_ADMISSION_SECONDS", 0.01)

    def verify(_token):
        entered.set()
        assert release.wait(3)
        return identity

    monkeypatch.setattr(auth, "verify_oidc_token", verify)

    async def run():
        first = _connection()
        request = asyncio.create_task(auth.require_principal_in_request_context(request=first))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            with pytest.raises(HTTPException) as error:
                await auth.require_principal_in_request_context(request=_connection())
            assert error.value.status_code == 503
            assert not hasattr(first.state, "principal")
        finally:
            release.set()
        limiter = asyncio.get_running_loop()._lightwork_oidc_slots
        await asyncio.wait_for(limiter.acquire(), 1)
        limiter.release()
        assert paths.current_tenant_id() is None
    asyncio.run(run())
