"""Start-up says loudly when outside-agent governance is on but nobody would
be told: alerts off, alerts with no channel, or no channel that is ready."""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

WEBHOOK = "https://prod-00.example.invalid/workflows/abc/triggers/manual/paths/invoke?sig=s3cr3t-signature"  # pragma: allowlist secret


@pytest.fixture
def settings(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    for name in ("MAVERICK_ALERTS", "TEAMS_NOTIFY_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)

    def write(text: str) -> None:
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()

    write("")
    yield write
    config.reset_config_cache()


def test_alerts_off_is_warned_about(settings, caplog):
    from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

    with caplog.at_level(logging.WARNING, logger="maverick.ops_alert"):
        said = warn_if_alerts_cannot_reach_anyone()
    assert "alerts are switched off" in said and "nobody will be told" in said and "Second Shift" in said
    assert any("switched off" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)


def test_alerts_on_with_nowhere_to_go_is_warned_about(settings):
    from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

    settings("[alerts]\nenabled = true\n")
    assert "no channel to go to" in warn_if_alerts_cannot_reach_anyone()


def test_a_channel_that_is_not_ready_is_warned_about(settings):
    from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

    settings('[alerts]\nenabled = true\nbackends = ["teams"]\n')
    assert "no alert channel is ready" in warn_if_alerts_cannot_reach_anyone()


def test_a_working_channel_is_not_warned_about(settings, monkeypatch, caplog):
    from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

    monkeypatch.setenv("TEAMS_NOTIFY_WEBHOOK_URL", WEBHOOK)
    settings('[alerts]\nenabled = true\nbackends = ["teams"]\n')
    with caplog.at_level(logging.WARNING, logger="maverick.ops_alert"):
        assert warn_if_alerts_cannot_reach_anyone() == ""
    assert caplog.records == []


def test_nothing_is_said_when_outside_agent_governance_is_off(settings, monkeypatch):
    from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS")
    assert warn_if_alerts_cannot_reach_anyone() == ""


def test_the_web_app_logs_the_warning_when_it_starts(settings, caplog):
    from maverick_dashboard.app import app

    with caplog.at_level(logging.WARNING, logger="maverick.ops_alert"):
        with TestClient(app, base_url="http://127.0.0.1"):
            pass
    assert any("alerts are switched off" in r.getMessage() for r in caplog.records)


def test_the_warning_never_holds_a_webhook_address(settings, monkeypatch):
    from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

    monkeypatch.setenv("TEAMS_NOTIFY_WEBHOOK_URL", WEBHOOK)
    said = warn_if_alerts_cannot_reach_anyone()
    assert "s3cr3t-signature" not in said and "example.invalid" not in said
