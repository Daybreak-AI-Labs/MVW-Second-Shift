"""The drift panel on an agent's page: the field-level difference as a short
list, what the person can do, old records without details, and everything
from a platform escaped."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from maverick import agent_drift as drift
from maverick import agent_watch as watch
from maverick import agent_watch_changes as changes
from maverick import agent_watch_microsoft  # noqa: F401 -- registers the built-in checks
from maverick import external_agents as xa

T0 = 20_000 * 86400
AGENT = "guest-help"
EVIL = "<script>alert(1)</script>"


class _Stub:
    agents: list = []

    def list_agents(self):
        return list(_Stub.agents)


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    monkeypatch.setattr(watch, "_FACTORIES", dict(watch._FACTORIES))
    watch._load_watchers()
    watch.register("foundry", lambda settings: _Stub())
    _Stub.agents = []
    (tmp_path / "config.toml").write_text(
        '[agent_watch]\nenable = true\nplatforms = ["foundry"]\n'
        '[agent_watch.foundry]\nx = 1\n', encoding="utf-8")
    config.reset_config_cache()
    from maverick_dashboard.app import app
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c
    config.reset_config_cache()


def _enroll(client, ref: str = "foundry:proj/guest-help") -> None:
    r = client.post("/api/v1/external-agents", json={"id": AGENT, "platform": "custom", "owner": "ops@example.com"})
    assert r.status_code == 201, r.text
    path = xa.registry_path()
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[AGENT]["external_ref"] = ref
    path.write_text(json.dumps(entries), encoding="utf-8")


def _seen(model: str, tool: str = "web_search", name: str = "Guest Help Desk", described: bool = True):
    details = changes.describe("foundry", {
        "name": name, "version": "7", "model": model, "tools": [tool],
        "tool_settings": {tool: changes.digest(tool)}, "instructions": changes.digest("x" + model)}
    ) if described else {}
    return watch.ObservedAgent(platform="foundry", external_id="proj/guest-help", name=name, version="7",
                               state="enabled", binding_strength=watch.IMMUTABLE_REVISION, details=details,
                               fingerprint=watch.fingerprint({"m": model, "t": tool}))


def _drifted(client, **after) -> None:
    _enroll(client)
    _Stub.agents = [_seen("gpt-4.1", described=after.pop("described_before", True))]
    watch.sync(now=T0)
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=T0 + 60)
    _Stub.agents = [_seen(**after)]
    watch.sync(now=T0 + 7200)


def _page(client) -> str:
    r = client.get(f"/external-agents/{AGENT}")
    assert r.status_code == 200, r.text
    return r.text


def test_the_page_lists_what_changed_as_field_before_now(client):
    _drifted(client, model="gpt-4.1-mini", tool="function:send_email")
    html = _page(client)
    assert "Guest Help Desk changed on Microsoft Foundry" in html
    assert "<caption class=\"sr-only\">What changed in this agent's set-up</caption>" in html
    assert "<th scope=\"row\">Model</th><td class=\"muted\">gpt-4.1</td><td>gpt-4.1-mini</td>" in html
    assert "function:send_email" in html and "Second Shift keeps a fingerprint of the instructions" in html
    assert "sha256:" not in html  # no raw digests shown to a person


def test_everything_from_the_platform_is_escaped(client):
    _drifted(client, model=EVIL, tool=f"function:{EVIL}", name=f"Desk {EVIL}")
    html = _page(client)
    assert EVIL not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_the_page_says_what_the_person_can_do(client):
    _drifted(client, model="gpt-4.1-mini")
    html = _page(client)
    assert "What you can do" in html
    assert "approve it as the baseline" in html and 'id="drift-approve"' in html
    assert 'href="/agent-control-plane"' in html and "Pause it from Agent control" in html
    # Foundry cannot be switched off from here: the page says so and what to do instead
    assert "Foundry portal" in html and 'id="platform-switch"' not in html


def test_a_record_from_before_details_were_kept_says_so_and_does_not_fail(client):
    _drifted(client, model="gpt-4.1-mini", described_before=False)
    html = _page(client)
    assert "Details were not recorded for this change." in html
    assert "What changed in this agent" not in html  # no list of fields to show
    assert "no longer matches the approved one" in html


def test_a_platform_that_cannot_be_switched_off_says_what_the_administrator_does(client):
    _enroll(client, ref="workday:acme/abc")
    html = _page(client)
    assert "Agent Management Hub" in html and 'id="platform-switch"' not in html


def test_an_agent_with_no_platform_link_still_shows_its_page(client):
    r = client.post("/api/v1/external-agents", json={"id": AGENT, "platform": "custom", "owner": "ops@example.com"})
    assert r.status_code == 201
    html = _page(client)
    assert 'id="agent-drift"' in html and 'id="platform-switch"' not in html


class _Entra(_Stub):
    """A platform check that can switch agents off, and says it is allowed to."""

    allow_switch_off = True

    def __init__(self, settings: dict) -> None:
        pass

    def switch(self, external_id: str, *, enabled: bool) -> None:
        raise AssertionError("the page must never switch anything off by itself")


def test_the_switch_off_button_shows_only_where_it_can_be_used(client, tmp_path):
    from maverick import config
    watch.register("entra_agent_id", _Entra)
    (tmp_path / "config.toml").write_text(
        '[agent_watch]\nenable = true\nplatforms = ["entra_agent_id"]\n[agent_watch.entra_agent_id]\nx = 1\n',
        encoding="utf-8")
    config.reset_config_cache()
    _enroll(client, ref="entra_agent_id:1b7313c4-05d0-4a08-88e3-7b76c003a0a2")
    html = _page(client)
    assert 'id="platform-switch"' in html and 'data-action="off"' in html
    assert "Switch off at Microsoft Entra Agent ID" in html
    assert 'id="platform-switch" data-action="off" data-platform="Microsoft Entra Agent ID" data-name="' in html
    _Entra.allow_switch_off = False
    try:
        html = _page(client)
    finally:
        _Entra.allow_switch_off = True
    assert 'id="platform-switch"' not in html and "allow_switch_off = true" in html
