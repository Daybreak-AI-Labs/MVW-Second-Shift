"""Agent spend, calendar grouping and budget projections use recorded costs."""
from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

import pytest

from tests.new import signin_kit as kit

_NOW = datetime(2026, 11, 16, tzinfo=UTC)


@pytest.fixture(scope="module")
def signing_key():
    return kit.new_key()


@pytest.fixture
def installation(tmp_path, monkeypatch, request, signing_key):
    stop = kit.start(tmp_path, monkeypatch, request, signing_key)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    try:
        yield
    finally:
        stop()


def _cost(world, *, owner, domain, amount, ended):
    goal = world.create_goal("Unshown run title", owner=owner, domain=domain)
    eid = world.start_episode(goal)
    if ended is not None:
        world.end_episode(eid, "Unshown run output", "success", cost_dollars=amount)
        with world._writing() as conn:
            conn.execute("UPDATE episodes SET ended_at=? WHERE id=?", (ended.timestamp(), eid))


@pytest.fixture
def report_data(installation, monkeypatch):
    from maverick import external_agents
    from maverick_dashboard._shared import _world

    roster = [
        {"id": "alpha", "platform_label": "Foundry", "period_spent": 80.0, "period": "monthly", "max_dollars": 100.0},
        {"id": "beta", "platform_label": "Custom", "period_spent": 70.0, "period": "total", "max_dollars": 100.0},
        {"id": "quiet", "platform_label": "Custom", "period_spent": 0.0, "period": "monthly", "max_dollars": None},
    ]
    monkeypatch.setattr(external_agents, "roster", lambda: roster)
    world = _world()
    _cost(world, owner="agent:alpha", domain="Sales", amount=50, ended=datetime(2026, 11, 2, tzinfo=UTC))
    _cost(world, owner="agent:alpha", domain="Support", amount=30, ended=datetime(2026, 11, 7, tzinfo=UTC))
    _cost(world, owner="agent:beta", domain="=inside", amount=10, ended=datetime(2026, 11, 15, tzinfo=UTC))
    _cost(world, owner="agent:beta", domain="Support", amount=60, ended=datetime(2026, 10, 31, 23, 59, 59, 999900, tzinfo=UTC))
    _cost(world, owner="agent:retired", domain="", amount=3, ended=datetime(2026, 10, 15, tzinfo=UTC))
    _cost(world, owner="user:private", domain="Personal", amount=5000, ended=datetime(2026, 11, 8, tzinfo=UTC))
    _cost(world, owner="agent:quiet", domain="Open", amount=1000, ended=None)
    _cost(world, owner="agent:quiet", domain="Old", amount=1000, ended=datetime(2025, 9, 15, tzinfo=UTC))
    return world


def _totals(rows):
    return {row["label"]: (row["dollars"], row["runs"]) for row in rows}


def test_report_groups_completed_agent_runs_and_forecasts_against_each_limit(report_data):
    from maverick.spend_reporting import report

    result = report(report_data, now=_NOW)
    assert _totals(result["agents"]) == {"alpha": (80, 2), "beta": (70, 2), "retired": (3, 1)}
    assert _totals(result["departments"]) == {"Support": (90, 2), "Sales": (50, 1), "=inside": (10, 1), "Unassigned": (3, 1)}
    assert _totals(result["platforms"]) == {"Foundry": (80, 2), "Custom": (70, 2), "Unknown platform": (3, 1)}
    assert _totals(result["months"])["2026-11"] == (90, 3)
    limits = {row["label"]: row for row in result["budgets"]}
    assert limits["alpha"]["projected_dollars"] == 160
    assert limits["alpha"]["projected_over_limit"] is True
    assert limits["beta"]["projected_dollars"] == 80
    assert limits["beta"]["projected_over_limit"] is False
    assert limits["quiet"]["limit_dollars"] is None


def test_view_can_read_page_api_and_csv_with_the_same_rows(report_data, signing_key, monkeypatch):
    from maverick import spend_reporting
    from maverick_dashboard import spend_api
    from maverick_dashboard.app import app

    monkeypatch.setattr(spend_api, "report", lambda world: spend_reporting.report(world, now=_NOW))
    viewer = kit.client_for(app, signing_key, "viewer")
    page = viewer.get("/spend")
    assert page.status_code == 200 and 'href="/spend"' in page.text
    assert "Unshown run title" not in page.text and "Unshown run output" not in page.text
    result = viewer.get("/api/v1/spend").json()
    download = viewer.get("/api/v1/spend.csv")
    assert download.status_code == 200 and "second-shift-spend.csv" in download.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(download.text)))
    assert len(rows) == sum(len(result[name]) for name in ("agents", "departments", "platforms", "months", "budgets"))
    assert any(row["label"] == "'=inside" for row in rows)
    assert result["total_dollars"] == 153


def test_a_signed_in_person_without_the_view_permission_is_refused(installation, signing_key, monkeypatch):
    from maverick_dashboard import rbac
    from maverick_dashboard.app import app

    monkeypatch.setattr(rbac, "default_role", lambda: None)

    caller = kit.client_for(app, signing_key, "none")
    for path in ("/spend", "/api/v1/spend", "/api/v1/spend.csv"):
        assert caller.get(path).status_code == 403
