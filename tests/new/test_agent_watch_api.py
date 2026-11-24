"""The operator API for platform checks, through the web app."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from maverick import agent_watch as watch
from maverick import (
    agent_watch_microsoft,  # noqa: F401 -- registers the built-in checks before any test copies the registry
)

T0 = 20_000 * 86400


class FakeWatcher:
    """A platform that lists whatever the test put in ``agents``."""

    name = "fake"
    agents: list[watch.ObservedAgent] = []
    calls = 0

    def __init__(self, settings: dict) -> None:
        pass

    def list_agents(self) -> list[watch.ObservedAgent]:
        FakeWatcher.calls += 1
        return list(FakeWatcher.agents)


def _seen(external_id: str, config: str = "v1") -> watch.ObservedAgent:
    return watch.ObservedAgent(platform="fake", external_id=external_id, name=external_id.title(),
                               version="1", state="enabled",
                               fingerprint=watch.fingerprint({"config": config}))


def _mounted(app, router) -> bool:
    return any(getattr(route, "original_router", None) is router
               or getattr(route, "path", "") == "/api/v1/agent-watch" for route in app.routes)


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.setattr(watch, "_FACTORIES", {**watch._FACTORIES, "fake": FakeWatcher})
    FakeWatcher.agents, FakeWatcher.calls = [], 0
    (tmp_path / "config.toml").write_text(
        '[agent_watch]\nenable = true\nplatforms = ["fake"]\n', encoding="utf-8")
    config.reset_config_cache()
    from maverick_dashboard.agent_watch_api import router
    from maverick_dashboard.app import app

    if not _mounted(app, router):  # the app includes the router itself once it is wired in
        app.include_router(router)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c
    config.reset_config_cache()


def _enroll(client, agent_id: str, ref: str) -> None:
    from maverick import external_agents

    r = client.post("/api/v1/external-agents", json={"id": agent_id, "platform": "custom", "owner": "ops@example.com"})
    assert r.status_code == 201, r.text
    path = external_agents.registry_path()
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[agent_id]["external_ref"] = ref
    path.write_text(json.dumps(entries), encoding="utf-8")


def _as(monkeypatch, role: str) -> list[str]:
    """Answer the next requests as a signed-in person with ``role``; returns the permissions asked for."""
    from fastapi import HTTPException

    from maverick_dashboard import agent_watch_api, rbac

    asked: list[str] = []

    def require(_request, permission):
        asked.append(permission)
        if permission not in rbac.permissions_for(role):
            raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(agent_watch_api, "require_permission", require)
    return asked


def test_everything_answers_not_found_while_governance_is_off(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert client.get("/api/v1/agent-watch").status_code == 404
    assert client.post("/api/v1/agent-watch/sync").status_code == 404
    assert FakeWatcher.calls == 0


def test_status_before_any_check(client):
    body = client.get("/api/v1/agent-watch").json()
    assert body["enabled"] is True and body["not_enrolled"] == [] and body["problems"] == []
    row, = body["platforms"]
    assert (row["name"], row["ready"], row["last_attempt_at"]) == ("fake", True, None)
    assert FakeWatcher.calls == 0  # reading never asks a platform


def test_a_check_can_be_run_and_its_result_read(client):
    _enroll(client, "helpdesk", "fake:bot-1")
    FakeWatcher.agents = [_seen("bot-1"), _seen("bot-2")]
    ran = client.post("/api/v1/agent-watch/sync")
    assert ran.status_code == 200, ran.text
    summary = ran.json()
    assert summary["ran"] is True
    assert summary["platforms"]["fake"] == {"ok": True, "error": "", "listed": 2, "matched": 1,
                                            "not_enrolled": 1, "missing": 0}

    body = client.get("/api/v1/agent-watch").json()
    row, = body["platforms"]
    assert (row["listed"], row["matched"], row["not_enrolled"], row["last_error"]) == (2, 1, 1, "")
    found, = body["not_enrolled"]
    assert (found["platform"], found["external_id"], found["external_ref"]) == ("fake", "bot-2", "fake:bot-2")
    assert body["not_enrolled_count"] == 1


def test_while_checks_are_off_the_api_says_so_and_asks_no_platform(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_WATCH", "0")
    body = client.get("/api/v1/agent-watch").json()
    assert body["enabled"] is False and "turned off" in body["reason"]
    ran = client.post("/api/v1/agent-watch/sync")
    assert ran.status_code == 200
    assert ran.json()["ran"] is False and "turned off" in ran.json()["reason"]
    assert FakeWatcher.calls == 0


def test_a_failed_platform_is_an_ordinary_answer_with_a_plain_reason(client, monkeypatch):
    def refused(self):
        raise watch.WatchError("The platform refused this check (HTTP 403).")

    monkeypatch.setattr(FakeWatcher, "list_agents", refused)
    ran = client.post("/api/v1/agent-watch/sync")
    assert ran.status_code == 200
    assert ran.json()["platforms"]["fake"] == {"ok": False, "error": "The platform refused this check (HTTP 403)."}
    row, = client.get("/api/v1/agent-watch").json()["platforms"]
    assert row["last_error"] == "The platform refused this check (HTTP 403)." and row["failures_in_a_row"] == 1


def test_reading_needs_view_and_running_a_check_needs_admin(client, monkeypatch):
    asked = _as(monkeypatch, "viewer")
    assert client.get("/api/v1/agent-watch").status_code == 200
    assert client.post("/api/v1/agent-watch/sync").status_code == 403
    assert asked == ["view", "admin"] and FakeWatcher.calls == 0

    _as(monkeypatch, "operator")
    assert client.get("/api/v1/agent-watch").status_code == 200
    assert client.post("/api/v1/agent-watch/sync").status_code == 403
    assert FakeWatcher.calls == 0

    _as(monkeypatch, "admin")
    assert client.post("/api/v1/agent-watch/sync").status_code == 200
    assert FakeWatcher.calls == 1


def test_someone_with_no_role_can_read_nothing(client, monkeypatch):
    _as(monkeypatch, "nobody")
    assert client.get("/api/v1/agent-watch").status_code == 403
    assert client.post("/api/v1/agent-watch/sync").status_code == 403


def test_the_permission_is_checked_before_saying_whether_governance_is_on(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    _as(monkeypatch, "viewer")
    assert client.post("/api/v1/agent-watch/sync").status_code == 403


def test_a_request_from_another_origin_cannot_start_a_check(client):
    from maverick_dashboard.app import app

    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/api/v1/agent-watch/sync").status_code == 403
    assert FakeWatcher.calls == 0


def test_a_record_that_cannot_be_read_is_a_503_and_is_left_alone(client):
    client.post("/api/v1/agent-watch/sync")
    path = watch.store_path()
    path.write_text("{ not json", encoding="utf-8")
    calls = FakeWatcher.calls
    for answer in (client.get("/api/v1/agent-watch"), client.post("/api/v1/agent-watch/sync")):
        assert answer.status_code == 503 and "cannot be read" in answer.json()["detail"]
    assert path.read_text(encoding="utf-8") == "{ not json" and FakeWatcher.calls == calls


def test_a_check_takes_no_address_or_other_input_from_the_caller(client):
    FakeWatcher.agents = [_seen("bot-1")]
    ran = client.post("/api/v1/agent-watch/sync?url=https://evil.example/&platform=other",
                      json={"url": "https://evil.example/", "platforms": ["other"], "now": 1})
    assert ran.status_code == 200 and list(ran.json()["platforms"]) == ["fake"]
    assert ran.json()["at"] > T0  # the caller cannot set the clock either
    assert client.put("/api/v1/agent-watch").status_code == 405
    assert client.delete("/api/v1/agent-watch/sync").status_code == 405
