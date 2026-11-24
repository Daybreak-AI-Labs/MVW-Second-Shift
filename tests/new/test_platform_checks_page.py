"""What the Outside agents page shows about platform checks."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from maverick import agent_watch as watch
from maverick import (
    agent_watch_microsoft,  # noqa: F401 -- registers the built-in checks before any test copies the registry
)


class FakePlatform:
    """A platform that lists whatever the test put in ``agents``, or fails."""

    name = "fake"
    agents: list[watch.ObservedAgent] = []
    fails = False

    def __init__(self, settings: dict) -> None:
        pass

    def list_agents(self) -> list[watch.ObservedAgent]:
        if FakePlatform.fails:
            raise watch.WatchError("The platform did not answer.")
        return list(FakePlatform.agents)


def _seen(external_id: str, name: str) -> watch.ObservedAgent:
    return watch.ObservedAgent(platform="fake", external_id=external_id, name=name, version="1",
                               state="enabled", fingerprint=watch.fingerprint({"config": "v1"}))


@pytest.fixture
def settings(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.setattr(watch, "_FACTORIES", {**watch._FACTORIES, "fake": FakePlatform})
    FakePlatform.agents, FakePlatform.fails = [], False

    def write(text: str) -> None:
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()

    write('[agent_watch]\nenable = true\nplatforms = ["fake"]\n')
    yield write
    config.reset_config_cache()


@pytest.fixture
def client(settings):
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def _panel(client) -> str:
    page = client.get("/external-agents")
    assert page.status_code == 200
    return page.text.split('id="platform-checks"', 1)[1].split('id="xa-add"', 1)[0]


def _roster(client) -> str:
    """The roster: agents the checks found, and agents added here, in one list."""
    page = client.get("/external-agents")
    assert page.status_code == 200
    return page.text.split('id="xa-roster"', 1)[1].split('id="xa-connect"', 1)[0]


def test_the_page_says_when_platform_checks_are_off(client, settings):
    settings("")
    panel = _panel(client)
    assert "Platform checks are turned off." in panel and "data-ref=" not in panel


def test_a_platform_not_checked_yet_is_shown_as_such(client):
    assert "Fake: not checked yet" in _panel(client)


def test_an_agent_nobody_added_is_listed_with_the_reference_to_claim_it(client):
    FakePlatform.agents = [_seen("a-1", "Refund <b>bot</b>"), _seen("a-2", "Invoice helper")]
    assert client.post("/api/v1/agent-watch/sync").status_code == 200
    assert "2 agents are on your platforms but not added here" in _panel(client)
    roster = _roster(client)
    assert "Refund &lt;b&gt;bot&lt;/b&gt;" in roster and "<b>bot</b>" not in roster
    assert 'data-ref="fake:a-1"' in roster and 'data-level="watched"' in roster and "fake:a-2" in roster


def test_claiming_an_agent_takes_it_off_the_list(client):
    FakePlatform.agents = [_seen("a-1", "Refund bot"), _seen("a-2", "Invoice helper")]
    client.post("/api/v1/agent-watch/sync")
    added = client.post("/api/v1/external-agents", json={
        "id": "refund-bot", "platform": "custom", "owner": "ops@example.com", "external_ref": "fake:a-1"})
    assert added.status_code == 201, added.text
    assert "1 agent is on your platforms but not added here" in _panel(client)  # at once, without waiting for a check
    roster = _roster(client)
    assert 'data-ref="fake:a-1"' not in roster and 'data-ref="fake:a-2"' in roster
    client.post("/api/v1/agent-watch/sync")
    assert "1 agent is on your platforms but not added here" in _panel(client)
    roster = _roster(client)
    assert 'data-ref="fake:a-1"' not in roster and 'data-ref="fake:a-2"' in roster


def test_a_failed_check_is_shown_with_its_plain_reason(client):
    FakePlatform.fails = True
    client.post("/api/v1/agent-watch/sync")
    panel = _panel(client)
    assert "Fake: last check failed" in panel and "The platform did not answer." in panel


def test_the_panel_is_left_out_while_governance_is_off(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert 'id="platform-checks"' not in client.get("/external-agents").text


def test_a_record_that_cannot_be_read_does_not_break_the_page(client):
    from maverick import external_agents

    FakePlatform.agents = [_seen("a-1", "Refund bot")]
    client.post("/api/v1/agent-watch/sync")
    store = external_agents.registry_path().with_name("external_agents_watch.json")
    assert store.exists()
    store.write_text("{not json", encoding="utf-8")
    panel = _panel(client)
    assert "could not be read" in panel and "data-ref=" not in panel
    assert store.read_text(encoding="utf-8") == "{not json"  # never replaced
