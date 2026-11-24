"""Regression contracts for the public request and browser security boundaries."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request


def test_company_sessions_default_to_eight_hours(tmp_path, monkeypatch):
    from maverick.config import get_auth_sessions

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    assert get_auth_sessions()["company_hours"] == 8


def test_full_origin_for_writes():
    from maverick_dashboard.app import _is_same_origin

    scope = {
        "type": "http", "method": "POST", "scheme": "https", "path": "/",
        "server": ("example.test", 443),
        "headers": [(b"host", b"example.test"), (b"origin", b"http://example.test")],
    }
    assert _is_same_origin(Request(scope)) is False


@pytest.mark.asyncio
async def test_absent_agent_credential_leaves_body_unread(monkeypatch):
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    bytes_read = 0

    async def body():
        nonlocal bytes_read
        bytes_read += 2
        yield b"{}"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        response = await client.post("/api/v1/external/screen", content=body())
    assert response.status_code == 401
    assert bytes_read == 0


@pytest.mark.asyncio
async def test_gateway_validation_error_uses_fixed_fields():
    from fastapi.exceptions import RequestValidationError

    from maverick_dashboard.app import validation_exception_handler

    request = Request({"type": "http", "method": "POST", "path": "/api/v1/external/runs", "headers": []})
    error = RequestValidationError([{
        "loc": ("body", "title", "user-defined-map-index"), "input": "input-value",
        "msg": "user-derived-assertion", "ctx": {"extra": "context-value"},
    }])
    response = await validation_exception_handler(request, error)
    assert response.status_code == 422
    assert all(value not in response.body for value in
               (b"user-defined-map-index", b"input-value", b"user-derived-assertion", b"context-value"))


def test_smtp_password_requires_tls():
    from maverick.notifications import backend_status

    status = backend_status("email", {"email": {
        "host": "127.0.0.1", "port": 25, "tls": "none", "user": "sender",
        "from_address": "sender@example.test", "to": "recipient@example.test",
    }})
    assert status["ready"] is False


def test_each_break_glass_write_checks_audit(monkeypatch):
    import maverick.audit
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "_break_glass_last_audit", [None])
    answers = iter([True, False])
    monkeypatch.setattr(maverick.audit, "audit_event", lambda *args, **kwargs: next(answers))
    request = SimpleNamespace(method="POST", client=None, url=SimpleNamespace(path="/settings"))
    auth._audit_break_glass(request)
    with pytest.raises(HTTPException) as refusal:
        auth._audit_break_glass(request)
    assert refusal.value.status_code == 503


def test_v2_signing_input_commits_the_request_target():
    from maverick import external_identity

    target = external_identity.SignedTarget("POST", b"/api/v1/external/screen", b"", "https://example.test")
    value = external_identity.request_message_v2("ed25519", "sample-agent", "1700000000", "nonce", b"{}", target)
    assert b"/api/v1/external/screen" in value and b"https://example.test" in value
    assert b"POST" in value and b"sample-agent" in value
    for field, change in (
        ("method", "GET"), ("raw_path", b"/api/v1/external/runs"), ("query", b"order=2"), ("origin", "https://other.test"),
    ):
        assert external_identity.request_message_v2(
            "ed25519", "sample-agent", "1700000000", "nonce", b"{}", replace(target, **{field: change}),
        ) != value
