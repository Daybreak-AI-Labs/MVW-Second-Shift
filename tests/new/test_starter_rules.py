"""Starter rule sets for a new outside agent: values, recording, and that the person's edits win."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from maverick import starter_rules


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c
    config.reset_config_cache()


def test_the_module_says_these_are_starting_points():
    doc = starter_rules.__doc__.lower()
    assert "starting points" in doc and "not policy" in doc and "administrator" in doc


def test_each_starter_has_its_values():
    got = {key: starter_rules.values(key) for key in starter_rules.STARTERS}
    assert got == {
        "customer_facing": {"max_risk": "low", "approval_at": "medium", "max_dollars": 25.0,
                            "budget_period": "monthly", "expires_days": 30},
        "internal_helper": {"max_risk": "medium", "approval_at": "high", "max_dollars": 100.0,
                            "budget_period": "monthly", "expires_days": 90},
        "finance_hr": {"max_risk": "medium", "approval_at": "medium", "max_dollars": 25.0,
                       "budget_period": "monthly", "expires_days": 30},
    }
    assert starter_rules.values("nope") is None


def test_the_strict_starters_are_stricter_than_the_moderate_one():
    risk = {"low": 0, "medium": 1, "high": 2}
    strict = starter_rules.values("customer_facing"), starter_rules.values("finance_hr")
    easy = starter_rules.values("internal_helper")
    for rules in strict:
        assert risk[rules["approval_at"]] <= risk[easy["approval_at"]]
        assert rules["max_dollars"] < easy["max_dollars"] and rules["expires_days"] < easy["expires_days"]
    assert starter_rules.values("finance_hr")["approval_at"] == "medium"


def test_what_the_person_set_wins_over_the_starter():
    merged = starter_rules.resolve("customer_facing", {"max_dollars": 5.0, "max_risk": None})
    assert merged["max_dollars"] == 5.0 and merged["max_risk"] is None  # "no limit" is a choice too
    assert merged["approval_at"] == "medium" and merged["expires_days"] == 30  # not mentioned: the starter's
    with pytest.raises(ValueError):
        starter_rules.resolve("nope", {})


def test_values_returned_are_copies():
    starter_rules.values("finance_hr")["max_dollars"] = 1e9
    assert starter_rules.values("finance_hr")["max_dollars"] == 25.0


def test_enrolling_with_a_starter_fills_the_limits_and_remembers_it(client):
    r = client.post("/api/v1/external-agents", json={"id": "helper", "platform": "custom", "starter": "finance_hr"})
    assert r.status_code == 201, r.text
    row, = [a for a in client.get("/api/v1/external-agents").json()["agents"] if a["id"] == "helper"]
    assert (row["max_risk"], row["max_dollars"], row["period"]) == ("medium", 25.0, "monthly")
    assert row["approval_at"] == "medium" and row["starter"] == "finance_hr"


def test_edits_made_before_saving_are_what_is_saved(client):
    r = client.post("/api/v1/external-agents", json={
        "id": "helper", "platform": "custom", "starter": "customer_facing",
        "max_risk": "medium", "max_dollars": 7.5, "approval_at": "high", "budget_period": "total"})
    assert r.status_code == 201, r.text
    row, = client.get("/api/v1/external-agents").json()["agents"]
    assert (row["max_risk"], row["max_dollars"], row["period"], row["approval_at"]) == ("medium", 7.5, "total", "high")
    assert row["starter"] == "customer_facing"  # which starter was used is kept even when edited


def test_an_unknown_starter_is_refused_in_plain_words(client):
    r = client.post("/api/v1/external-agents", json={"id": "helper", "platform": "custom", "starter": "nope"})
    assert r.status_code == 400 and "starter" in r.json()["detail"].lower()


def test_a_person_must_approve_at_the_agents_own_floor(client, tmp_path):
    from maverick import external_agents as xa

    xa.enroll("fin-bot", "custom", max_risk="high", approval_at="medium",
              allow_tools=["lookup:low", "pay:medium"], expires_days=30, max_dollars=10.0)
    xa.enroll("easy-bot", "custom", max_risk="high", allow_tools=["lookup:low", "pay:medium"],
              expires_days=30, max_dollars=10.0)
    assert xa.screen("fin-bot", "lookup")["allowed"] is True
    held = xa.screen("fin-bot", "pay")
    assert held["allowed"] is False and held.get("requires_approval") is True
    assert xa.screen("easy-bot", "pay")["allowed"] is True  # the organisation-wide floor is "high"
