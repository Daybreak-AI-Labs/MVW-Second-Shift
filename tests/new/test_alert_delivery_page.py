"""What the Outside agents page shows about alert delivery."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

WEBHOOK = "https://prod-00.example.invalid/workflows/abc/triggers/manual/paths/invoke?sig=s3cr3t-signature"  # pragma: allowlist secret


@pytest.fixture
def settings(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
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


@pytest.fixture
def client(settings):
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def _strip(client) -> str:
    page = client.get("/external-agents")
    assert page.status_code == 200
    return page.text.split('id="alert-delivery"', 1)[1].split("<script", 1)[0]


def test_the_page_says_when_nobody_is_told(client):
    strip = _strip(client)
    assert "Alerts are off" in strip and "nobody is told" in strip


def test_alerts_that_are_on_with_no_channel_are_called_out(client, settings):
    settings("[alerts]\nenabled = true\n")
    assert "Alerts are on but have nowhere to go" in _strip(client)


def test_a_ready_channel_is_shown_without_its_address(client, settings, monkeypatch):
    monkeypatch.setenv("TEAMS_NOTIFY_WEBHOOK_URL", WEBHOOK)
    settings('[alerts]\nenabled = true\nbackends = ["teams"]\n')
    page = client.get("/external-agents").text
    assert "Alerts by Teams: ready" in page
    assert "s3cr3t-signature" not in page and "prod-00.example.invalid" not in page


def test_a_channel_that_is_not_ready_says_why(client, settings):
    settings('[alerts]\nenabled = true\nbackends = ["teams", "email"]\n')
    strip = _strip(client)
    assert "Alerts by Teams: not ready" in strip and "No Teams webhook address is set." in strip
    assert "Alerts by email: not ready" in strip


def test_an_administrator_is_offered_the_test(client):
    assert 'id="alert-test"' in client.get("/external-agents").text
