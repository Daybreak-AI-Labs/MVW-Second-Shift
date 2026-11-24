"""Tests for notifications (maverick.notifications)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_notifications_no_backends_no_op():
    from maverick.notifications import notify
    assert notify("hi", backends=["none"]) == 0


def test_notifications_unknown_backend_logs(monkeypatch):
    from maverick.notifications import notify
    fired = notify("hi", backends=["garbage"], async_dispatch=False)
    assert fired == 0  # nothing succeeded


def test_notifications_dispatch_with_ntfy_topic_env(monkeypatch):
    """With MAVERICK_NTFY_TOPIC + no SDK, dispatch attempts the call."""
    monkeypatch.setenv("MAVERICK_NTFY_TOPIC", "test-topic")
    from maverick import notifications

    posted: list[tuple[str, str]] = []

    def _fake_post(url, content=None, headers=None, timeout=None):
        posted.append((url, headers.get("Title", "")))
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch("httpx.post", side_effect=_fake_post):
        fired = notifications.notify(
            "test body", title="Hello", backends=["ntfy"], async_dispatch=False,
        )
    assert fired == 1
    assert len(posted) == 1
    assert "test-topic" in posted[0][0]
