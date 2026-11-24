"""Server-side session record: register, list, end one, end all, prune."""
from __future__ import annotations

import pytest
from maverick import config
from maverick_dashboard import session_registry as sr


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    config.reset_config_cache()
    # The throttle and the open store connection are process-wide: one test's
    # refresh must not throttle the next test's touch, nor keep its file open.
    sr._TOUCHED.clear()
    yield
    sr._drop_shared()
    sr._TOUCHED.clear()
    config.reset_config_cache()


@pytest.mark.parametrize("ua, expected", [
    ("", "Unknown device"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1", "Safari on iPhone"),
    ("Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", "Firefox on Linux"),
    ("python-httpx/0.27", "Program"),
])
def test_user_agent_summary(ua, expected):
    assert sr.user_agent_summary(ua) == expected
