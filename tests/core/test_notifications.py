"""Tests for notifications (maverick.notifications)."""
from __future__ import annotations


def test_notifications_no_backends_no_op():
    from maverick.notifications import notify
    assert notify("hi", backends=["none"]) == 0


def test_notifications_unknown_backend_logs(monkeypatch):
    from maverick.notifications import notify
    fired = notify("hi", backends=["garbage"], async_dispatch=False)
    assert fired == 0  # nothing succeeded
