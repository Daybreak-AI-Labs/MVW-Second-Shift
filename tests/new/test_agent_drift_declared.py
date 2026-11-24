"""A released agent's declared configuration becomes the approved one for drift checks."""
from __future__ import annotations

import pytest

from maverick import agent_drift as drift
from maverick import external_agents as xa

DAY = 86400
T0 = 20_000 * DAY
AGENT = "factory-helper"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _at(day, hour=12):
    return T0 + day * DAY + hour * 3600


def _baselined():
    xa.enroll(AGENT, "custom", description="helper", owner="alice", allow_tools=["create_word_document:low"], enrolled_by="carol")
    drift.observe_run(AGENT, cost_dollars=0.1, declared={"version": "1", "model": "gpt-a", "config_digest": "cfg-1"}, now=_at(0))
    drift.approve_baseline(AGENT, actor="carol", force=True, now=_at(1))


def _kinds(result):
    return {f["kind"] for f in result["findings"]}


def test_the_new_release_becomes_the_approved_configuration():
    _baselined()
    drift.observe_run(AGENT, cost_dollars=0.1, declared={"version": "2", "model": "gpt-a", "config_digest": "cfg-2"}, now=_at(2))
    assert {"config_changed", "version_changed"} <= _kinds(drift.evaluate(AGENT, now=_at(3)))
    assert drift.approve_declared_configuration(AGENT, version="2", config_digest="cfg-2", model="gpt-a", actor="carol") is True
    assert drift.baseline(AGENT)["config"]["declared"]["config_digest"] == "cfg-2"
    assert not ({"config_changed", "version_changed"} & _kinds(drift.evaluate(AGENT, now=_at(3))))
    # An agent still running the old configuration is now the one that drifted.
    drift.observe_run(AGENT, cost_dollars=0.1, declared={"version": "1", "model": "gpt-a", "config_digest": "cfg-1"}, now=_at(4))
    assert "config_changed" in _kinds(drift.evaluate(AGENT, now=_at(5)))


def test_it_changes_only_the_declared_fingerprints_and_is_audited(monkeypatch):
    _baselined()
    before = drift.baseline(AGENT)
    rows = []
    monkeypatch.setattr(drift, "_audit", lambda kind, agent_id, **payload: rows.append((kind, agent_id, payload)) or True)
    drift.approve_declared_configuration(AGENT, version="2", config_digest="cfg-2", model="gpt-b", actor=" carol ")
    after = drift.baseline(AGENT)
    assert after["approved_by"] == before["approved_by"] == "carol" and after["approved_at"] == before["approved_at"]
    assert after["config"]["declared"]["config_digest"] == "cfg-2" and after["config"]["declared"]["model"] == "gpt-b"
    assert rows == [("agent_declared_configuration_approved", AGENT, {"approved_by": "carol", "version": "2", "config_digest": "cfg-2", "model": "gpt-b"})]


def test_it_does_nothing_when_drift_is_off_and_says_why_it_failed_otherwise(tmp_path):
    from maverick import config

    _baselined()
    (tmp_path / "config.toml").write_text("[agent_drift]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert drift.enabled() is False
    assert drift.approve_declared_configuration(AGENT, version="2", config_digest="cfg-2", model="m", actor="carol") is False
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    with pytest.raises(drift.AgentDriftError):
        drift.approve_declared_configuration("ghost", version="2", config_digest="cfg-2", model="m", actor="carol")
    with pytest.raises(drift.AgentDriftError):
        drift.approve_declared_configuration(AGENT, version="2", config_digest="cfg-2", model="m", actor="  ")


def test_with_no_baseline_yet_the_declared_fingerprints_are_what_the_first_baseline_will_keep():
    xa.enroll(AGENT, "custom", description="helper", owner="alice", allow_tools=["create_word_document:low"], enrolled_by="carol")
    drift.approve_declared_configuration(AGENT, version="1", config_digest="cfg-1", model="gpt-a", actor="carol")
    drift.observe_run(AGENT, cost_dollars=0.1, now=_at(0))
    drift.approve_baseline(AGENT, actor="carol", force=True, now=_at(1))
    assert drift.baseline(AGENT)["config"]["declared"]["config_digest"] == "cfg-1"
