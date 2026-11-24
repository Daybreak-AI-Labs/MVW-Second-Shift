"""Every dashboard request is size-capped before any parser reads it."""
from __future__ import annotations
from maverick_dashboard import request_size
from maverick_dashboard.request_size import RequestSizeLimitMiddleware


def test_the_cap_comes_from_settings(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_REQUEST_MB", "2")
    assert request_size.max_request_bytes() == 2 * 1024 * 1024
    for bad in ("0", "-5", "nan", "lots"):
        monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_REQUEST_MB", bad)
        assert request_size.max_request_bytes() == request_size.DEFAULT_MAX_REQUEST_MB * 1024 * 1024


def test_the_dashboard_uses_the_cap(monkeypatch):
    from maverick_dashboard.app import app
    assert any(m.cls is RequestSizeLimitMiddleware for m in app.user_middleware)
