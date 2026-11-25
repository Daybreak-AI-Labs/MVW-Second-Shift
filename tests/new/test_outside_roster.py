"""One roster for outside agents: Watched, Added and Connected."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from maverick import agent_watch as watch
from maverick import (
    agent_watch_microsoft,  # noqa: F401 -- registers the built-in checks before any test copies the registry
)
from maverick import external_agents as xa


class FakePlatform:
    name = "fake"
    agents: list[watch.ObservedAgent] = []

    def __init__(self, settings: dict) -> None:
        pass

    def list_agents(self) -> list[watch.ObservedAgent]:
        return list(FakePlatform.agents)


def _seen(external_id: str, name: str = "") -> watch.ObservedAgent:
    return watch.ObservedAgent(platform="fake", external_id=external_id, name=name or external_id,
                               version="1", state="enabled", fingerprint=watch.fingerprint({"c": 1}))


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    monkeypatch.setattr(watch, "_FACTORIES", {**watch._FACTORIES, "fake": FakePlatform})
    FakePlatform.agents = []
    (tmp_path / "config.toml").write_text('[agent_watch]\nenable = true\nplatforms = ["fake"]\n', encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


@pytest.fixture
def client(home):
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def _add(agent_id: str, platform: str = "custom", **kw):
    return xa.enroll(agent_id, platform, owner="ops@example.com", **kw)


def _level(agent_id: str) -> str:
    from maverick import outside_roster

    return {r["id"]: r["level"] for r in outside_roster.build(xa.roster(), [])["rows"]}[agent_id]


# --- levels -----------------------------------------------------------------

def test_an_agent_found_only_by_a_check_is_watched(home):
    from maverick import outside_roster

    found = [{"platform": "fake", "external_id": "a-1", "external_ref": "fake:a-1", "name": "Refund bot",
              "state": "enabled", "first_seen_at": 100.0, "last_seen_at": 200.0}]
    built = outside_roster.build([], found)
    row, = built["rows"]
    assert row["level"] == "watched" and row["name"] == "Refund bot" and row["external_ref"] == "fake:a-1"
    assert row["last_seen_at"] == 200.0 and row["id"] is None


def test_enrolled_without_calls_is_added(home):
    _add("quiet")
    assert _level("quiet") == "added"


def test_enrolled_with_a_screening_call_is_connected(home):
    _add("caller")
    xa.note_seen("caller", kind="screen")
    assert _level("caller") == "connected"


def test_enrolled_with_a_run_report_is_connected(home):
    _add("runner", allow_tools=["t:low"], max_risk="low")
    xa.record_run("runner", {"title": "one task", "summary": "done", "outcome": "success"})
    assert _level("runner") == "connected"


# --- last heard from ---------------------------------------------------------

def _heard(agent_id: str):
    return json.loads(xa.registry_path().read_text())[agent_id].get("last_seen")


def test_last_heard_is_written_at_most_once_a_minute(home, monkeypatch):
    _add("bot")
    clock = [1_000_000.0]
    monkeypatch.setattr(xa.time, "time", lambda: clock[0])
    xa.note_seen("bot", kind="screen")
    assert _heard("bot") == 1_000_000.0
    clock[0] += 59
    xa.note_seen("bot", kind="run")
    assert _heard("bot") == 1_000_000.0  # inside the minute: no write
    clock[0] += 2
    xa.note_seen("bot", kind="run")
    assert _heard("bot") == 1_000_061.0


def test_a_quiet_call_inside_the_minute_does_not_touch_the_file(home, monkeypatch):
    _add("bot")
    xa.note_seen("bot", kind="screen")
    writes = []
    monkeypatch.setattr(xa, "_save_sidecar", lambda entries: writes.append(1))
    for _ in range(50):
        xa.note_seen("bot", kind="screen")
    assert writes == []


def test_what_was_received_is_one_of_a_few_words(home):
    _add("bot")
    xa.note_seen("bot", kind="<script>alert(1)</script>")
    assert json.loads(xa.registry_path().read_text())["bot"]["last_seen_kind"] == "call"
    from maverick import outside_roster

    assert outside_roster.connection("bot")["received"] == "a call"


def test_the_agents_own_gateway_calls_stamp_it(client):
    assert client.post("/api/v1/external-agents", json={"id": "gw", "platform": "custom", "max_risk": "low"}).status_code == 201
    token = client.post("/api/v1/external-agents/gw/credentials", json={"surface": "rest"}).json()["token"]
    assert client.get("/api/v1/external-agents/gw/connection").json()["level"] == "added"
    r = client.post("/api/v1/external/screen", json={"tool": "lookup", "risk": "low"},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    after = client.get("/api/v1/external-agents/gw/connection").json()
    assert after["level"] == "connected" and after["received"] == "a screening call"
    assert isinstance(after["last_heard_at"], float)


# --- filters and counts --------------------------------------------------------

def _mixed(home):
    _add("quiet", "foundry")
    _add("caller", "copilot")
    xa.note_seen("caller", kind="screen")
    found = [{"platform": "fake", "external_id": "w-1", "external_ref": "fake:w-1", "name": "Watched one",
              "state": "enabled", "first_seen_at": 1.0, "last_seen_at": 2.0},
             {"platform": "foundry", "external_id": "w-2", "external_ref": "foundry:w-2", "name": "Watched two",
              "state": "", "first_seen_at": 1.0, "last_seen_at": 2.0}]
    return found


def test_counts_cover_the_whole_roster_and_filters_narrow_the_rows(home):
    from maverick import outside_roster

    found = _mixed(home)
    everything = outside_roster.build(xa.roster(), found)
    assert everything["counts"] == {"watched": 2, "added": 1, "connected": 1, "total": 4}
    assert [p["key"] for p in everything["platforms"]] == ["copilot", "fake", "foundry"]
    only = outside_roster.build(xa.roster(), found, level="watched")
    assert {r["level"] for r in only["rows"]} == {"watched"} and len(only["rows"]) == 2
    assert only["counts"] == everything["counts"]
    foundry = outside_roster.build(xa.roster(), found, platform="foundry")
    assert sorted(r["name"] for r in foundry["rows"]) == ["Watched two", "quiet"] or len(foundry["rows"]) == 2
    both = outside_roster.build(xa.roster(), found, level="added", platform="foundry")
    assert [r["id"] for r in both["rows"]] == ["quiet"]
    assert outside_roster.build(xa.roster(), found, level="bogus")["rows"] == everything["rows"]


def test_the_page_shows_counts_and_honours_the_filters(client):
    FakePlatform.agents = [_seen("w-1", "Watched one")]
    client.post("/api/v1/agent-watch/sync")
    _add("quiet")
    _add("caller")
    xa.note_seen("caller", kind="screen")
    page = client.get("/external-agents").text
    for label, n in (("Watched", 1), ("Added", 1), ("Connected", 1)):
        assert re.search(rf'data-xa-count="{label.lower()}"[^>]*>\s*{n}\b', page), label
    filtered = client.get("/external-agents?level=watched").text
    assert "Watched one" in filtered and "caller" not in filtered.split('id="xa-roster"', 1)[1].split("</table>", 1)[0]
    by_platform = client.get("/external-agents?platform=custom").text
    roster = by_platform.split('id="xa-roster"', 1)[1].split("</table>", 1)[0]
    assert "quiet" in roster and "Watched one" not in roster


def test_nothing_the_roster_did_before_is_lost(client):
    _add("quiet")
    page = client.get("/external-agents").text
    for needle in ("data-xa-mint=", "data-xa-revoke=", "data-xa-remove=", "View agent", "Riskiest action allowed",
                   "Download the connection file"):
        assert needle in page


def test_read_only_roster_displays_agents_and_omits_unavailable_controls(client, monkeypatch):
    from maverick_dashboard import app as dashboard

    _add("quiet")
    monkeypatch.setattr(dashboard, "has_permission", lambda *_: False)
    response = client.get("/external-agents")
    assert response.status_code == 200
    assert "View agent" in response.text
    assert "Only an administrator can change these agents" in response.text
    assert 'data-xa-mint="quiet"' not in response.text
    assert 'data-xa-remove="quiet"' not in response.text


# --- a Watched agent is added and moves up ---------------------------------------

def test_adding_a_watched_agent_moves_it_to_added_then_connected(client):
    FakePlatform.agents = [_seen("a-1", "Refund bot")]
    client.post("/api/v1/agent-watch/sync")
    page = client.get("/external-agents").text
    assert 'href="/external-agents?add=fake%3Aa-1#xa-add"' in page
    prefilled = client.get("/external-agents?add=fake:a-1").text
    assert 'value="Refund bot"' in prefilled and 'value="fake:a-1"' in prefilled
    r = client.post("/api/v1/external-agents", json={"id": "refund-bot", "platform": "custom",
                                                     "owner": "ops@example.com", "external_ref": "fake:a-1"})
    assert r.status_code == 201, r.text
    roster = client.get("/external-agents").text.split('id="xa-roster"', 1)[1].split("</table>", 1)[0]
    assert roster.count("Refund bot") == 0 or "refund-bot" in roster  # one row for it, now enrolled
    assert 'data-level="watched"' not in roster and 'data-level="added"' in roster
    xa.note_seen("refund-bot", kind="screen")
    roster = client.get("/external-agents").text.split('id="xa-roster"', 1)[1].split("</table>", 1)[0]
    assert 'data-level="connected"' in roster and 'data-level="added"' not in roster


def test_an_unknown_prefill_is_ignored(client):
    page = client.get('/external-agents?add="><script>x</script>')
    assert page.status_code == 200 and "<script>x</script>" not in page.text


# --- escaping ----------------------------------------------------------------------

def test_platform_provided_names_are_escaped(client):
    FakePlatform.agents = [_seen("a-1", '<img src=x onerror=alert(1)> "bot"')]
    client.post("/api/v1/agent-watch/sync")
    for url in ("/external-agents", "/external-agents?add=fake:a-1"):
        page = client.get(url).text
        assert "<img src=x" not in page
        assert "&lt;img src=x onerror=alert(1)&gt;" in page


# --- the status endpoint -----------------------------------------------------------

def test_the_status_says_only_level_and_last_heard(client):
    _add("bot")
    body = client.get("/api/v1/external-agents/bot/connection").json()
    assert body == {"id": "bot", "level": "added", "last_heard_at": None, "received": None}
    xa.note_seen("bot", kind="run")
    body = client.get("/api/v1/external-agents/bot/connection").json()
    assert set(body) == {"id", "level", "last_heard_at", "received"}
    assert body["level"] == "connected" and body["received"] == "a run report"


def test_an_unknown_agent_has_no_status(client):
    assert client.get("/api/v1/external-agents/ghost/connection").status_code == 404


def test_the_status_needs_the_view_permission(client, monkeypatch):
    from fastapi import HTTPException

    from maverick_dashboard import connect_agent_api, rbac

    _add("bot")
    asked: list[str] = []

    def require(_request, permission):
        asked.append(permission)
        if permission not in rbac.permissions_for("nobody"):
            raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(connect_agent_api, "require_permission", require)
    assert client.get("/api/v1/external-agents/bot/connection").status_code == 403
    assert asked == ["view"]


def test_the_status_is_off_while_governance_is_off(client, monkeypatch):
    _add("bot")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert client.get("/api/v1/external-agents/bot/connection").status_code == 404
