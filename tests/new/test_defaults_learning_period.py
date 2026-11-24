"""A quieter first few weeks for drift: for ``[agent_drift] learning_days``
(14 by default) after a baseline is approved, findings are recorded and shown
marked "learning period" but not alerted and never contain the agent. The one
exception is a high-severity change to the agent's set-up on its home
platform. Once the period ends, a finding that is still there is reported."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from maverick import agent_drift as drift
from maverick import external_agents as xa
from tests.new import test_agent_drift as base

AGENT = base.AGENT
DAY = base.DAY
_at, _seed, _enroll = base._at, base._seed, base._enroll
#: Approved at the end of day 13: the period runs to the end of day 27.
_APPROVED = _at(13, 23)
_ENDS = _APPROVED + 14 * DAY
_NEW_TOOL = {"crm_update": 14, "research": 5, "wire_transfer": 1}


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


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit_pkg
    rows: list[dict] = []
    monkeypatch.setattr(audit_pkg, "record", lambda kind, *, agent="system", goal_id=None, **p:
                        rows.append({"kind": str(kind), **p}) or True)
    return rows


@pytest.fixture
def alerts(monkeypatch):
    from maverick import ops_alert
    sent: list[dict] = []
    monkeypatch.setattr(ops_alert, "alert", lambda event, detail="", *, severity="high":
                        sent.append({"event": event, "detail": detail, "severity": severity}) or True)
    return sent


def _baselined() -> None:
    _enroll()
    _seed(range(14))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_APPROVED)


def _drift_on_day(day: int) -> float:
    """A high-severity finding (a new tool) on ``day``; returns when to judge."""
    _seed([day], tools=_NEW_TOOL)
    return _at(day, 23)


def test_the_default_is_fourteen_days_and_zero_turns_it_off(tmp_path):
    assert drift.settings()["learning_days"] == 14
    base._configure(tmp_path, "[agent_drift]\nlearning_days = 0\n")
    assert drift.settings()["learning_days"] == 0
    base._configure(tmp_path, "[agent_drift]\nlearning_days = 21\n")
    assert drift.settings()["learning_days"] == 21


def test_findings_in_the_learning_period_are_recorded_and_shown_but_not_alerted(audit_rows, alerts):
    _baselined()
    moment = _drift_on_day(15)
    result = drift.check(AGENT, now=moment)
    assert result["new_findings"] == ["new_tool:wire_transfer"] and result["contained"] is False
    finding, = result["findings"]
    assert finding["learning"] is True and finding["severity"] == "high"
    assert result["learning_period"] == {"active": True, "ends_at": _ENDS, "days": 14}
    detected, = [r for r in audit_rows if r["kind"] == "agent_drift_detected"]
    assert detected["learning_period"] is True
    assert alerts == []
    # The agent's page and the drift view still list it.
    assert drift.detail(AGENT, now=moment)["findings"][0]["key"] == "new_tool:wire_transfer"


def test_a_learning_finding_never_contains_the_agent(tmp_path, audit_rows, alerts):
    base._configure(tmp_path, '[agent_drift]\non_drift = "contain"\n')
    _baselined()
    result = drift.check(AGENT, now=_drift_on_day(15))
    assert result["contained"] is False and xa.containment_state(AGENT) is False
    assert not [r for r in audit_rows if r["kind"] == "external_agent_contained"]
    assert alerts == []


def test_a_finding_still_present_when_the_period_ends_is_alerted_and_contains(tmp_path, audit_rows, alerts):
    base._configure(tmp_path, '[agent_drift]\non_drift = "contain"\n')
    _baselined()
    moment = _drift_on_day(15)
    drift.check(AGENT, now=moment)
    assert alerts == []
    # Still the same finding after the last learning day: the period is over.
    _seed(range(26, 29), tools=_NEW_TOOL)
    after = drift.check(AGENT, now=_at(28, 23))
    assert after["learning_period"]["active"] is False
    assert after["new_findings"] == ["new_tool:wire_transfer"] and after["contained"] is True
    alert, = alerts
    assert "has moved away from its approved baseline" in alert["detail"]
    # Reported once, not again on the next check.
    assert drift.check(AGENT, now=_at(28, 23) + 900)["new_findings"] == []
    assert len(alerts) == 1


def test_the_period_ends_on_schedule(tmp_path):
    _baselined()
    assert drift.evaluate(AGENT, now=_ENDS - 1)["learning_period"]["active"] is True
    assert drift.evaluate(AGENT, now=_ENDS)["learning_period"]["active"] is False
    base._configure(tmp_path, "[agent_drift]\nlearning_days = 3\n")
    assert drift.evaluate(AGENT, now=_APPROVED + 3 * DAY + 1)["learning_period"]["active"] is False


def test_with_no_learning_period_a_finding_is_alerted_at_once(tmp_path, audit_rows, alerts):
    base._configure(tmp_path, "[agent_drift]\nlearning_days = 0\n")
    _baselined()
    result = drift.check(AGENT, now=_drift_on_day(15))
    assert result["findings"][0]["learning"] is False and len(alerts) == 1
    assert result["learning_period"]["ends_at"] is None


def test_a_high_severity_platform_change_always_alerts(tmp_path, audit_rows, alerts):
    base._configure(tmp_path, '[agent_drift]\non_drift = "contain"\n')
    _enroll()
    drift.observe_discovered(AGENT, version_digest="digest-1", binding_strength="exact",
                             source="copilot-studio", now=_at(0))
    _seed(range(14))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_APPROVED)
    _seed(range(15, 18))
    drift.observe_discovered(AGENT, version_digest="digest-2", source="copilot-studio", now=_at(17))
    result = drift.check(AGENT, now=_at(17, 23))
    finding, = result["findings"]
    assert finding["kind"] == "config_changed" and finding["learning"] is False
    assert result["learning_period"]["active"] is True
    assert result["contained"] is True and len(alerts) == 1


def test_a_medium_setup_change_the_agent_reports_waits_out_the_period(audit_rows, alerts):
    _enroll()
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(0))
    _seed(range(14))
    with drift._editing() as agents:
        agents[AGENT]["config"] = {"declared": {"model": "model-a"}}
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_APPROVED)
    with drift._editing() as agents:
        agents[AGENT]["config"] = {"declared": {"model": "model-b"}}
    _seed(range(15, 18))
    result = drift.check(AGENT, now=_at(17, 23))
    assert [f["kind"] for f in result["findings"]] == ["model_changed"]
    assert result["findings"][0]["learning"] is True and alerts == []


# ----------------------------------------------------------------- the page

@pytest.fixture
def client(tmp_path):
    from maverick_dashboard.app import app
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c


def test_the_agents_page_marks_findings_and_says_when_the_period_ends(client, monkeypatch):
    import time as real_time

    _enroll()
    now = real_time.time()
    # Activity on real days, so the page's own clock sees a baseline and a finding.
    today = int(now // DAY)
    with drift._editing() as agents:
        record = drift._record_for(agents, AGENT, drift._enrolled_ids())
        for day in range(today - 16, today - 2):
            bucket = drift._day_bucket(record, day * DAY + 43200)
            bucket.update(runs=10, screens=20, tool_calls=20, cost_dollars=5.0)
            bucket["tools"] = {"crm_update": 14, "research": 6}
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=(today - 2) * DAY + 43200)
    with drift._editing() as agents:
        record = drift._record_for(agents, AGENT, drift._enrolled_ids())
        bucket = drift._day_bucket(record, now)
        bucket.update(runs=10, screens=20, tool_calls=20, cost_dollars=5.0)
        bucket["tools"] = dict(_NEW_TOOL)
    page = client.get(f"/external-agents/{AGENT}")
    assert page.status_code == 200
    assert "Learning period until" in page.text and "Learning period</span>" in page.text
    assert "no alert is sent" in page.text
