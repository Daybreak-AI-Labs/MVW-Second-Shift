"""Reminders before a waiting request or an access key runs out: when they go
out, that each goes out once, that a restart never repeats one, and that a
decided request is left alone."""
from __future__ import annotations

import dataclasses
import time

import pytest

AGENT = "sf-helpdesk"
DAY = 86400


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture
def alerts(monkeypatch):
    from maverick import ops_alert

    sent: list[dict] = []

    def alert(event, detail="", *, severity="high"):
        sent.append({"event": event, "detail": detail, "severity": severity})
        return True

    monkeypatch.setattr(ops_alert, "alert", alert)
    return sent


@pytest.fixture
def teams(monkeypatch):
    from maverick import approval_notify

    cards: list[int] = []
    monkeypatch.setattr(approval_notify, "teams_approvals_enabled", lambda: True)
    monkeypatch.setattr(approval_notify, "approval_reminder",
                        lambda approval_id, world=None: cards.append(approval_id) or True)
    return cards


def _world(tmp_path):
    from maverick.world_model import WorldModel

    return WorldModel(tmp_path / "world.db")


def _park(world, *, ttl=3600, card=True) -> tuple[int, float, float]:
    """A waiting request; returns its id, when it was asked and its decide-by time."""
    from maverick.approval_cards import decode_approval_detail, encode_operation_approval_detail

    detail = encode_operation_approval_detail(
        action="external:sf-helpdesk:send_email", summary="Send the renewal email.",
        target_label="mail", target={"to": "x"}, parameters={"n": 1},
        parameter_summary=["Sends one email."], actor="agent:sf-helpdesk", role="agent",
        known_effects=["Sends one email."], unresolved_assumptions=[], before="Not sent.",
        after="Sent once.", irreversible=True, ttl_seconds=ttl) if card else "plain text"
    approval_id = world.create_approval("external:sf-helpdesk:send_email", risk="high", detail=detail,
                                        requested_by="agent:sf-helpdesk")
    asked = world.get_approval(approval_id).requested_at
    end = decode_approval_detail(detail)["expires_at"] if card else 0.0
    return approval_id, asked, end


# ------------------------------------------------------------------ approvals

def test_a_request_with_a_quarter_of_its_time_left_is_reminded_once(tmp_path, alerts, teams):
    from maverick import expiry_reminders as er

    world = _world(tmp_path)
    approval_id, _asked, end = _park(world)
    assert er.check_approvals(world, now=end - 3000)["reminded"] == []  # 83% left
    assert alerts == [] and teams == []
    assert er.check_approvals(world, now=end - 800)["reminded"] == [approval_id]  # 22% left
    reminder, = alerts
    assert reminder["event"] == "approval.reminder" and "Send the renewal email." in reminder["detail"]
    assert "Second Shift" in reminder["detail"] and teams == [approval_id]
    # Once only, however often the check runs.
    er.check_approvals(world, now=end - 700)
    er.check_approvals(world, now=end - 10)
    assert len(alerts) == 1 and teams == [approval_id]


def test_the_fraction_is_a_setting(tmp_path, alerts):
    from maverick import config
    from maverick import expiry_reminders as er

    (tmp_path / "config.toml").write_text("[approval]\nreminder_fraction_left = 0.5\n", encoding="utf-8")
    config.reset_config_cache()
    assert er.reminder_fraction() == 0.5
    world = _world(tmp_path)
    _id, _asked, end = _park(world)
    assert er.check_approvals(world, now=end - 1700)["reminded"] == [_id]


def test_the_default_fraction_is_a_quarter_and_zero_turns_reminders_off(tmp_path, alerts):
    from maverick import config
    from maverick import expiry_reminders as er

    assert er.reminder_fraction() == 0.25 and er.key_warning_days() == 14
    (tmp_path / "config.toml").write_text("[approval]\nreminder_fraction_left = 0\n", encoding="utf-8")
    config.reset_config_cache()
    world = _world(tmp_path)
    _park(world)
    assert er.check_approvals(world, now=time.time() + 3500)["reminded"] == []


def test_a_request_that_runs_out_undecided_gets_one_note(tmp_path, alerts):
    from maverick import expiry_reminders as er

    world = _world(tmp_path)
    approval_id, _asked, end = _park(world)
    assert er.check_approvals(world, now=end + 5)["expired"] == [approval_id]
    note, = alerts
    assert note["event"] == "approval.expired" and "ran out" in note["detail"] and "refused" in note["detail"]
    er.check_approvals(world, now=end + 600)
    assert len(alerts) == 1


def test_a_reminder_then_the_note_each_go_once_and_survive_a_restart(tmp_path, alerts):
    from maverick import expiry_reminders as er

    world = _world(tmp_path)
    _id, _asked, end = _park(world)
    er.check_approvals(world, now=end - 600)
    # "Restart": a new world handle, and the module keeps nothing in memory.
    world = _world(tmp_path)
    er.check_approvals(world, now=end - 300)
    er.check_approvals(world, now=end + 1)
    world = _world(tmp_path)
    er.check_approvals(world, now=end + 2)
    assert [a["event"] for a in alerts] == ["approval.reminder", "approval.expired"]
    assert er.sent_record()["approvals"]


def test_a_decided_request_is_never_reminded_or_noted(tmp_path, alerts, teams):
    from maverick import expiry_reminders as er

    world = _world(tmp_path)
    approval_id, _asked, end = _park(world)
    from maverick.channel_approvals import audit_approval_decision, record_vote

    event = record_vote(world, approval_id, "denied", "user:dana@northwind.example")
    assert audit_approval_decision(world, event) is True
    assert world.get_approval(approval_id).status == "denied"
    er.check_approvals(world, now=end - 600)
    er.check_approvals(world, now=end + 5)
    assert alerts == [] and teams == []


def test_a_request_without_a_decide_by_time_is_left_alone(tmp_path, alerts):
    from maverick import expiry_reminders as er

    world = _world(tmp_path)
    _park(world, card=False)
    assert er.check_approvals(world, now=time.time() + 10 * DAY) == {"reminded": [], "expired": []}
    assert alerts == []


def test_a_message_no_channel_accepted_is_tried_again(tmp_path, monkeypatch):
    from maverick import expiry_reminders as er
    from maverick import ops_alert

    outcomes = iter([False, True])
    sent: list[str] = []
    monkeypatch.setattr(ops_alert, "alert", lambda event, detail="", *, severity="high":
                        sent.append(event) or next(outcomes))
    world = _world(tmp_path)
    approval_id, _asked, end = _park(world)
    assert er.check_approvals(world, now=end - 600)["reminded"] == []
    assert er.check_approvals(world, now=end - 590)["reminded"] == [approval_id]
    assert er.check_approvals(world, now=end - 580)["reminded"] == []
    assert sent == ["approval.reminder", "approval.reminder"]


def test_nothing_is_sent_or_recorded_while_alerts_and_teams_are_off(tmp_path, monkeypatch, alerts):
    from maverick import config
    from maverick import expiry_reminders as er

    monkeypatch.setenv("MAVERICK_ALERTS", "0")
    config.reset_config_cache()
    world = _world(tmp_path)
    _id, _asked, end = _park(world)
    assert er.check_approvals(world, now=end - 600) == {"reminded": [], "expired": []}
    assert alerts == [] and er.sent_record() == {"approvals": {}, "keys": {}}


# ----------------------------------------------------------------------- keys

def _enroll(days: float | None):
    from maverick import external_agents as xa

    return xa.enroll(AGENT, "custom", description="help desk agent", owner="ops@northwind.example",
                     enrolled_by="admin@northwind.example", expires_days=days)


def _key_end() -> float:
    from maverick import agent_trust

    return agent_trust.load_registry(strict=True)[AGENT].expires_at


def test_a_key_ending_within_two_weeks_is_warned_about_once(alerts):
    from maverick import expiry_reminders as er

    _enroll(30)
    end = _key_end()
    assert er.check_keys(now=end - 20 * DAY) == {"warned": [], "ended": []}
    assert er.check_keys(now=end - 13 * DAY)["warned"] == [AGENT]
    warning, = alerts
    assert warning["event"] == "agent_key.expiring" and "help desk agent" in warning["detail"]
    er.check_keys(now=end - 5 * DAY)
    assert len(alerts) == 1


def test_an_ended_key_gets_one_note_and_a_restart_repeats_nothing(alerts):
    from maverick import expiry_reminders as er

    _enroll(30)
    end = _key_end()
    er.check_keys(now=end - 10 * DAY)
    assert er.check_keys(now=end + 60)["ended"] == [AGENT]
    er.check_keys(now=end + 3600)
    assert [a["event"] for a in alerts] == ["agent_key.expiring", "agent_key.expired"]
    assert "can no longer work" in alerts[1]["detail"]


def test_the_warning_window_is_a_setting(tmp_path, alerts):
    from maverick import config
    from maverick import expiry_reminders as er

    (tmp_path / "config.toml").write_text("[agent_keys]\nexpiry_warning_days = 30\n", encoding="utf-8")
    config.reset_config_cache()
    _enroll(40)
    assert er.check_keys(now=_key_end() - 25 * DAY)["warned"] == [AGENT]


def test_a_key_with_no_end_date_is_left_alone(alerts):
    from maverick import expiry_reminders as er

    _enroll(None)
    assert er.check_keys(now=time.time() + 400 * DAY) == {"warned": [], "ended": []}
    assert alerts == []


def test_a_renewed_key_is_warned_about_again(alerts):
    from maverick import expiry_reminders as er

    _enroll(30)
    end = _key_end()
    er.check_keys(now=end - 10 * DAY)
    from maverick import agent_trust
    # The same agent later holds a key with a new end date: a new key, a new warning.
    monkey_end = end + 90 * DAY
    real = agent_trust.load_registry

    def renewed(*a, **k):
        registry = real(*a, **k)
        registry[AGENT] = dataclasses.replace(registry[AGENT], expires_at=monkey_end)
        return registry

    agent_trust.load_registry = renewed
    try:
        er.check_keys(now=monkey_end - 5 * DAY)
    finally:
        agent_trust.load_registry = real
    assert len(alerts) == 2
