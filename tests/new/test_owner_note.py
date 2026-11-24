"""The weekly note to agent owners: what goes in it, when, and that it goes once.

Hermetic: the mail server and Teams are stand-ins that record what they are
given; everything else (roster, drift, keys, waiting requests, the record of
what was sent) is real.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from maverick import agent_owners, owner_note
from maverick import external_agents as xa

ME = "jo@example.com"
SECRET_TEXT = "SECRET-PROMPT-AND-OUTPUT"  # pragma: allowlist secret
DAY = 86400


def _next_monday(hour: int = 8, minute: int = 5) -> float:
    """A Monday at the given UTC time that is more than a day from now."""
    base = datetime.now(timezone.utc) + timedelta(days=2)
    base += timedelta(days=(0 - base.weekday()) % 7)
    return base.replace(hour=hour, minute=minute, second=0, microsecond=0).timestamp()


NOW = _next_monday()


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _configure(tmp_path, body: str = "enabled = true\n") -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text("[owner_note]\n" + body, encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture
def mail(monkeypatch):
    """A mail server that takes everything, and alerts by email that are set up."""
    from maverick import notifications

    sent: list[dict] = []

    def send_email(to, subject, text_body, *, html_body=None, cfg=None, headers=None):
        sent.append({"to": to, "subject": subject, "text": text_body, "html": html_body or ""})
        return True

    monkeypatch.setattr(notifications, "send_email", send_email)
    monkeypatch.setattr(owner_note, "email_ready", lambda: (True, ""))
    return sent


def _enroll(agent_id="helpdesk", owner=ME, **fields):
    return xa.enroll(agent_id, "custom", description=fields.pop("description", "Help desk agent"),
                     owner=owner, **fields)


def _meta(agent_id: str, **values) -> None:
    with xa._sidecar_locked():
        sidecar = xa._load_sidecar()
        sidecar[agent_id].update(values)
        xa._save_sidecar(sidecar)


def _quiet_agent(agent_id="helpdesk", **fields):
    """An agent that has been heard from and has nothing wrong."""
    _enroll(agent_id, **fields)
    _meta(agent_id, last_seen=NOW - 60, last_seen_kind="call", runs=3)


def _only(sent):
    assert len(sent) == 1
    return sent[0]


# -------------------------------------------------------------- off and ready

def test_off_by_default_even_with_mail_set_up(home, mail):
    _enroll()
    assert owner_note.run_due(now=NOW) == {"emailed": [], "teams": [], "nothing": []}
    assert mail == []
    assert owner_note.settings()["enabled"] is False


def test_nothing_is_sent_until_alerts_by_email_are_set_up(home, monkeypatch):
    from maverick import notifications

    sent = []
    monkeypatch.setattr(notifications, "send_email", lambda *a, **k: sent.append(a) or True)
    _configure(home)
    _enroll()
    assert owner_note.email_ready()[0] is False
    owner_note.run_due(now=NOW)
    assert sent == []


# ------------------------------------------------------------------- schedule

def test_defaults_are_monday_eight_utc(home):
    cfg = owner_note.settings()
    assert (cfg["weekday_name"], cfg["hour"], cfg["timezone"], cfg["problems"]) == ("monday", 8, "UTC", [])


def test_sends_at_the_scheduled_time_not_before(home, mail):
    _configure(home)
    _enroll()
    before = _next_monday(7, 59)
    assert owner_note.run_due(now=before)["emailed"] == []
    assert mail == []
    assert len(owner_note.run_due(now=_next_monday(8, 0))["emailed"]) == 1
    assert len(mail) == 1


def test_a_pass_long_after_the_time_does_not_send(home, mail):
    _configure(home)
    _enroll()
    owner_note.run_due(now=NOW + 13 * 3600)
    owner_note.run_due(now=NOW + 3 * DAY)
    assert mail == []


def test_weekday_hour_and_zone_are_settings(home, mail):
    _configure(home, 'enabled = true\nweekday = "friday"\nhour = 17\ntimezone = "America/New_York"\n')
    _enroll()
    friday = datetime.fromtimestamp(NOW, timezone.utc) + timedelta(days=4)  # 17:00 New York is 22:00 UTC in winter
    assert owner_note.scheduled_slot(friday.timestamp(), owner_note.settings()).weekday() == 4
    due = friday.replace(hour=22, minute=1).timestamp()
    early = friday.replace(hour=21, minute=0).timestamp()
    assert owner_note.run_due(now=early)["emailed"] == []
    assert len(owner_note.run_due(now=due)["emailed"]) == 1


def test_the_time_zone_moves_the_hour(home, mail):
    _configure(home, 'enabled = true\ntimezone = "America/New_York"\n')  # Monday 08:00 there is 13:00 UTC
    _enroll()
    assert owner_note.run_due(now=_next_monday(8, 5))["emailed"] == []
    assert len(owner_note.run_due(now=_next_monday(13, 5))["emailed"]) == 1


def test_bad_settings_fall_back_and_say_so(home):
    _configure(home, 'enabled = true\nweekday = "someday"\nhour = 31\ntimezone = "Mars/Base"\n')
    cfg = owner_note.settings()
    assert (cfg["weekday_name"], cfg["hour"], cfg["timezone"]) == ("monday", 8, "UTC")
    assert len(cfg["problems"]) == 3


# ----------------------------------------------------------------- once a week

def test_once_per_owner_and_week_across_a_restart(home, mail, monkeypatch):
    _configure(home)
    _enroll()
    owner_note.run_due(now=NOW)
    owner_note.run_due(now=NOW + 300)
    # A restart forgets every in-memory value; only the record on disk remains.
    import importlib
    importlib.reload(owner_note)
    monkeypatch.setattr(owner_note, "email_ready", lambda: (True, ""))
    owner_note.run_due(now=NOW + 600)
    assert len(mail) == 1


def test_the_next_week_sends_again(home, mail):
    _configure(home)
    _enroll()
    owner_note.run_due(now=NOW)
    owner_note.run_due(now=NOW + 7 * DAY)
    assert len(mail) == 2


def test_one_note_per_owner_listing_all_their_agents(home, mail):
    _configure(home)
    _enroll("a", description="Alpha agent")
    _enroll("b", description="Beta agent")
    _enroll("c", owner="kim@example.com", description="Gamma agent")
    owner_note.run_due(now=NOW)
    assert sorted(m["to"] for m in mail) == [ME, "kim@example.com"]
    jo = next(m for m in mail if m["to"] == ME)
    assert "Alpha agent" in jo["text"] and "Beta agent" in jo["text"] and "Gamma agent" not in jo["text"]


def test_a_failed_hand_over_is_tried_again_later_but_not_at_once(home, monkeypatch):
    from maverick import notifications

    _configure(home)
    _enroll()
    monkeypatch.setattr(owner_note, "email_ready", lambda: (True, ""))
    outcomes = iter([False, True])
    calls = []
    monkeypatch.setattr(notifications, "send_email", lambda *a, **k: calls.append(1) or next(outcomes))
    owner_note.run_due(now=NOW)
    owner_note.run_due(now=NOW + 60)
    assert len(calls) == 1
    owner_note.run_due(now=NOW + 3600)
    assert len(calls) == 2
    owner_note.run_due(now=NOW + 7200)
    assert len(calls) == 2


def test_the_record_holds_no_address(home, mail):
    _configure(home)
    _enroll()
    owner_note.run_due(now=NOW)
    assert ME not in (home / "owner_notes.json").read_text(encoding="utf-8")


# -------------------------------------------------------------- nothing to say

def test_nothing_to_report_sends_nothing(home, mail):
    _configure(home)
    _quiet_agent()
    result = owner_note.run_due(now=NOW)
    assert mail == [] and len(result["nothing"]) == 1


def test_agents_without_an_owner_address_are_skipped(home, mail):
    _configure(home)
    _enroll("a", owner="Jo Smith")
    _enroll("b", owner="")
    owner_note.run_due(now=NOW)
    assert mail == []


# ------------------------------------------------------------------- each item

def _views():
    return agent_owners.by_owner(now=NOW)[ME]


def _kinds():
    return [agent_owners.attention(v, NOW) for v in _views()][0]


def test_silent_agent(home):
    _enroll()
    assert _kinds() == ["silent"]


def test_a_just_added_agent_is_not_reported_as_silent(home):
    _enroll()
    assert agent_owners.attention(_views()[0], time.time()) == []


def test_blocked_agent(home):
    _quiet_agent()
    assert xa.contain("helpdesk")
    assert _kinds() == ["blocked"]


def test_paused_agent(home):
    from maverick.revocation import shared

    _quiet_agent()
    shared().revoke("agent:helpdesk", reason="paused")
    view = _views()[0]
    assert view["lifecycle_label"] == "Paused" and _kinds() == ["blocked"]


def test_spend_above_eighty_percent_only(home):
    _quiet_agent(max_dollars=100.0)
    _meta("helpdesk", period="monthly", period_key=xa._month_key(NOW), period_spent=79.0)
    assert _kinds() == []
    _meta("helpdesk", period_spent=80.0)
    assert _kinds() == ["spend"]


def test_key_ending_within_the_window_and_ended(home):
    from maverick import agent_trust

    _quiet_agent(expires_days=30)
    end = agent_trust.load_registry(strict=True)["helpdesk"].expires_at
    for moment, expect in ((end - 10 * DAY, ["key"]), (end - 40 * DAY, []), (end + DAY, ["key"])):
        view = agent_owners.by_owner(now=moment)[ME][0]
        assert agent_owners.attention(view, moment) == expect, moment


def test_requests_waiting_for_this_agent_only(home):
    from maverick.world_model import open_world

    _quiet_agent()
    _quiet_agent("other", owner="kim@example.com")
    open_world().create_approval("external:helpdesk:send", risk="high", detail="d", requested_by="agent:helpdesk",
                                 provenance="external_agents")
    open_world().create_approval("external:other:send", risk="high", detail="d", requested_by="agent:other",
                                 provenance="external_agents")
    assert _kinds() == ["requests"]
    assert _views()[0]["waiting"]["count"] == 1


def test_unacknowledged_drift_and_platform_change(home, monkeypatch):
    from maverick import agent_drift

    _quiet_agent()

    def evaluate(agent_id, **kw):
        return {"state": "drifted", "findings": [
            {"kind": "tool_mix", "severity": "medium", "summary": SECRET_TEXT, "acknowledged": False},
            {"kind": "config_changed", "source": "discovery", "severity": "high", "summary": SECRET_TEXT,
             "acknowledged": False},
            {"kind": "volume", "severity": "low", "summary": SECRET_TEXT, "acknowledged": True}]}

    monkeypatch.setattr(agent_drift, "evaluate", evaluate)
    assert _kinds() == ["platform", "drift"]
    assert _views()[0]["drift"]["open"] == 2


def test_agent_missing_on_its_platform(home, monkeypatch):
    from maverick import agent_watch

    _quiet_agent()
    monkeypatch.setattr(agent_watch, "platform_view", lambda agent_id: {
        "watched": True, "checked": True, "missing_on_platform": True, "last_checked_at": NOW})
    assert _kinds() == ["platform"]


def test_model_findings(home, monkeypatch):
    from maverick import model_register

    _quiet_agent()
    monkeypatch.setattr(model_register, "findings_for_agent",
                        lambda agent_id: [{"model": "gpt-x", "summary": SECRET_TEXT, "severity": "high"}])
    assert _kinds() == ["models"]


def test_an_unreadable_part_is_not_guessed_at(home, monkeypatch):
    from maverick import model_register

    _quiet_agent()

    def broken(agent_id):
        raise OSError("gone")

    monkeypatch.setattr(model_register, "findings_for_agent", broken)
    view = _views()[0]
    assert view["models"]["readable"] is False and _kinds() == []


# ----------------------------------------------------------------- the message

def _everything_wrong(monkeypatch):
    from maverick import agent_drift, model_register
    from maverick.world_model import open_world

    _enroll(max_dollars=100.0, expires_days=10, description="Help <b>desk</b> agent")
    _meta("helpdesk", period="monthly", period_key=xa._month_key(NOW), period_spent=90.0, contained=True)
    open_world().create_approval("external:helpdesk:send", risk="high", detail=SECRET_TEXT,
                                 requested_by="agent:helpdesk", provenance="external_agents")
    monkeypatch.setattr(agent_drift, "evaluate", lambda agent_id, **kw: {"state": "drifted", "findings": [
        {"kind": "tool_mix", "severity": "medium", "summary": SECRET_TEXT, "acknowledged": False},
        {"kind": "config_changed", "source": "discovery", "severity": "high", "summary": SECRET_TEXT,
         "acknowledged": False}]})
    monkeypatch.setattr(model_register, "findings_for_agent",
                        lambda agent_id: [{"model": "gpt-x", "summary": SECRET_TEXT, "severity": "high"}])


def test_the_note_lists_every_kind_of_item_with_links(home, mail, monkeypatch):
    monkeypatch.setenv("MAVERICK_PUBLIC_URL", "https://second-shift.example.com")
    _configure(home)
    _everything_wrong(monkeypatch)
    owner_note.run_due(now=NOW)
    note = _only(mail)
    assert note["to"] == ME
    for _kind, title in owner_note.SECTIONS:
        assert title in note["text"], title
    assert "https://second-shift.example.com/external-agents/helpdesk" in note["text"]
    assert "https://second-shift.example.com/my-agents" in note["text"]
    assert 'href="https://second-shift.example.com/external-agents/helpdesk"' in note["html"]
    assert "90% of its limit used this month" in note["text"]
    assert "1 request waiting" in note["text"]
    assert "Second Shift" in note["subject"] and "Lightwork" not in note["text"] + note["html"]


def test_the_note_holds_no_agent_content_or_secrets(home, mail, monkeypatch):
    _configure(home)
    _everything_wrong(monkeypatch)
    owner_note.run_due(now=NOW)
    note = _only(mail)
    blob = note["subject"] + note["text"] + note["html"]
    assert SECRET_TEXT not in blob
    assert "token" not in blob.lower() and "password" not in blob.lower()


def test_names_are_escaped_in_the_html_part(home, mail, monkeypatch):
    _configure(home)
    _everything_wrong(monkeypatch)
    owner_note.run_due(now=NOW)
    html = _only(mail)["html"]
    assert "<b>desk</b>" not in html
    assert "Help &lt;b&gt;desk&lt;/b&gt; agent" in html


def test_an_owner_address_that_is_several_addresses_gets_nothing(home, mail):
    _configure(home)
    _enroll("a", owner="a@example.com, b@example.com")
    _enroll("b", owner="Jo <jo@example.com>")
    owner_note.run_due(now=NOW)
    assert mail == []


# ----------------------------------------------------------------------- Teams

class _Connector:
    def __init__(self):
        self.activities = []

    def create_personal_conversation(self, service_url, *, member_id, tenant_id):
        return "conv-1"

    def send_activity(self, service_url, conversation_id, activity):
        self.activities.append((conversation_id, activity))
        return "act-1"


class _Bot:
    def __init__(self):
        self.connector = _Connector()
        self.settings = {"tenant_id": "t", "service_url": "https://smba.example/", "allowed_users": []}


@pytest.fixture
def teams(monkeypatch):
    from maverick import teams_identity
    from maverick_dashboard import teams_bot

    bot = _Bot()
    monkeypatch.setattr(owner_note, "teams_ready", lambda: True)
    monkeypatch.setattr(teams_bot, "build_bot", lambda **k: bot)
    monkeypatch.setattr(teams_identity, "resolve_principal", lambda oid, upn="": "user:jo" if upn == ME else None)
    monkeypatch.setattr(teams_identity, "reachable_people",
                        lambda: [{"teams_id": "29:jo", "principal": "user:jo", "conversation": None}])
    return bot


def test_teams_is_off_by_default(home, mail, teams):
    _configure(home)
    _enroll()
    owner_note.run_due(now=NOW)
    assert len(mail) == 1 and teams.connector.activities == []


def test_teams_message_goes_once_to_the_owner(home, mail, teams):
    _configure(home, "enabled = true\nteams = true\n")
    _enroll()
    owner_note.run_due(now=NOW)
    owner_note.run_due(now=NOW + 600)
    assert len(mail) == 1 and len(teams.connector.activities) == 1
    text = teams.connector.activities[0][1]["text"]
    assert "Help desk agent" in text and SECRET_TEXT not in text


def test_an_owner_teams_does_not_know_is_skipped_quietly(home, mail, teams):
    _configure(home, "enabled = true\nteams = true\n")
    _enroll(owner="kim@example.com")
    owner_note.run_due(now=NOW)
    owner_note.run_due(now=NOW + 3600)
    assert len(mail) == 1 and teams.connector.activities == []


def test_nothing_to_report_sends_no_teams_message(home, mail, teams):
    _configure(home, "enabled = true\nteams = true\n")
    _quiet_agent()
    owner_note.run_due(now=NOW)
    assert mail == [] and teams.connector.activities == []


# ------------------------------------------------------------------- the timer

@pytest.mark.asyncio
async def test_the_app_timer_runs_a_pass_and_survives_a_failure(monkeypatch):
    import asyncio

    from maverick_dashboard import app as dashboard

    passes = []

    def run_due():
        passes.append(1)
        if len(passes) == 1:
            raise RuntimeError("mail server down")

    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(owner_note, "run_due", run_due)
    monkeypatch.setattr(dashboard.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        await dashboard._owner_note_loop()
    assert len(passes) == 2


# ------------------------------------------------------------------- Postgres

def test_with_postgres_what_was_sent_is_kept_there_and_still_goes_once(home, mail, records_in_postgres):
    from tests.new.conftest import saved_records

    _configure(home)
    _enroll()
    owner_note.run_due(now=NOW)
    owner_note.run_due(now=NOW + 300)
    assert len(mail) == 1
    assert not (home / "owner_notes.json").exists()
    assert "owner_notes.json" in saved_records(records_in_postgres)
    assert [row["state"] for row in owner_note.sent_record().values()] == ["sent"]


def test_with_postgres_a_damaged_record_is_refused_not_read_as_empty(home, mail, records_in_postgres):
    from maverick import record_documents

    _configure(home)
    _enroll()
    record_documents.at(owner_note._path()).write_text("[1]")
    with pytest.raises(ValueError, match="not an object"):
        owner_note.run_due(now=NOW)
    assert mail == []
