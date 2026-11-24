"""The settings an administrator may change in the product: the allowlist, validation, the layer the
changes are kept in, locks, per-call effect, fail-closed reads and the audit entry for each change.

Hermetic: a throwaway data folder and deployment file per test; the audit log is captured."""
from __future__ import annotations

import os

import pytest

from maverick import config
from maverick import editable_settings as es
from maverick.editable_settings import SettingRefused

ACTOR = "user:boss"


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    monkeypatch.delenv(config.CONFIG_OVERLAY_ENV, raising=False)
    for setting in es.SETTINGS:
        for name in setting.env:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("TEAMS_NOTIFY_WEBHOOK_URL", raising=False)
    rows: list[dict] = []

    def record(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "record", record)
    config.reset_config_cache()
    yield rows
    config.reset_config_cache()


@pytest.fixture
def audit(installation):
    return installation


def deployment(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


def row(key: str) -> dict:
    return es.setting_view(key)


def a_valid_value(setting: es.Setting):
    """A value the setting takes that differs from its default."""
    kind = setting.kind
    if kind == "bool":
        return not bool(setting.default)
    if kind == "int":
        low, high = int(setting.minimum), int(setting.maximum)
        return low + 1 if setting.default == low else low
    if kind == "float":
        low, high = float(setting.minimum), float(setting.maximum)
        return high if setting.default != high else low
    if kind == "choice":
        return next(c for c in setting.choices if c != setting.default)
    if kind == "text":
        return "dep-1" if setting.pattern is es._DEPLOYMENT else ("C1:abc" if setting.pattern is es._CHANNEL else "https://second-shift.example.com")
    if kind == "guid":
        return "11111111-2222-3333-4444-555555555555"
    if kind == "env_name":
        return "SS_SOME_NAME"
    if kind == "list_choice":
        return [setting.choices[0]]
    if kind == "list_guid":
        return ["11111111-2222-3333-4444-555555555555"]
    if kind == "list_text":
        return ["ops@example.com"]
    if kind == "map":
        return {"0c6b1c52-8a6e-4f0e-9a43-6a8f2b1d9c11": "contoso.crm.dynamics.com"}
    raise AssertionError(kind)


def a_wrong_value(setting: es.Setting):
    kind = setting.kind
    if kind == "bool":
        return "true"
    if kind in ("int", "float"):
        return setting.maximum + 1
    if kind in ("choice", "list_choice"):
        return "no-such-choice" if kind == "choice" else ["no-such-choice"]
    if kind == "env_name":
        return "p@ssw0rd-Secret!"
    if kind in ("guid", "text"):
        return "not valid \x00 value"
    if kind in ("list_guid", "list_text"):
        return ["not valid \x00 value"]
    return "x"


# ------------------------------------------------------------------------ the allowlist

def test_the_allowlist_is_complete_and_described():
    sections = {s.id for s in es.SECTIONS}
    assert {s.section for s in es.SETTINGS} == sections
    for setting in es.SETTINGS:
        assert setting.label and setting.help and setting.help.endswith(".")
        assert setting.kind in {"bool", "int", "float", "choice", "text", "guid", "env_name", "list_choice",
                                "list_guid", "list_text", "map"}
        if setting.kind in ("int", "float"):
            assert setting.minimum is not None and setting.maximum is not None
        if setting.kind in ("choice", "list_choice"):
            assert setting.choices
    counts = {s.id: sum(1 for x in es.SETTINGS if x.section == s.id) for s in es.SECTIONS}
    assert all(counts.values()), counts


def test_ranges_follow_the_readers():
    from maverick import agent_drift, agent_watch, model_drift

    for name, (_kind, default, low, high) in agent_drift._NUMBER_SETTINGS.items():
        s = es.get(f"agent_drift.{name}")
        assert (s.default, s.minimum, s.maximum) == (default, low, high)
    for name, (_default, _low, high) in agent_watch._NUMBER_SETTINGS.items():
        if name == "sync_minutes":
            assert es.get("agent_watch.sync_minutes").maximum == high
    for name, (_kind, _default, _low, high) in model_drift._NUMBER_SETTINGS.items():
        assert es.get(f"model_drift.{name}").maximum == high


@pytest.mark.parametrize("setting", es.SETTINGS, ids=lambda s: s.key)
def test_every_setting_takes_its_own_kind_of_value_and_refuses_others(setting):
    good = a_valid_value(setting)
    assert es.validate(setting, good) is not None
    with pytest.raises(SettingRefused) as refused:
        es.validate(setting, a_wrong_value(setting))
    assert refused.value.status == 422


@pytest.mark.parametrize("key", [s.key for s in es.SETTINGS if s.kind in ("int", "float")])
def test_numbers_outside_their_range_and_odd_numbers_are_refused(key):
    s = es.get(key)
    for bad in (s.minimum - 1, s.maximum + 1, True, "5", None, float("nan"), float("inf")):
        with pytest.raises(SettingRefused):
            es.validate(s, bad)
    es.validate(s, s.minimum)
    es.validate(s, s.maximum)
    if s.kind == "int":
        with pytest.raises(SettingRefused):
            es.validate(s, s.minimum + 0.5)


def test_unknown_keys_are_refused():
    for key in ("alerts.nope", "providers.anthropic.api_key", "notifications.teams_webhook", "notifications.email.password",
                "settings.locked", "../etc", "", "alerts"):
        with pytest.raises(SettingRefused) as refused:
            es.change(key, True, actor=ACTOR)
        assert refused.value.status == 404, key


# ----------------------------------------------------------------------------- secrets

SECRETISH = ["sk-ant-api03-AbCdEf123456", "p@ssw0rd!", "https://hooks.example.com/abc", "my secret value",
             "abc.def", "lowercase_secret", "a" * 65, "", "VALUE WITH SPACE", "A=B", "${HOME}"]


@pytest.mark.parametrize("key", [s.key for s in es.SETTINGS if s.kind == "env_name"])
def test_a_credential_setting_takes_a_variable_name_never_a_secret(key, audit):
    for text in SECRETISH:
        with pytest.raises(SettingRefused) as refused:
            es.change(key, text, actor=ACTOR)
        assert text not in str(refused.value) or text == ""
    assert not [r for r in audit if r["kind"] == "setting_changed"]
    assert not es.layer_path().exists()


def test_the_value_of_a_credential_variable_is_never_shown_only_whether_it_is_set(tmp_path, monkeypatch):
    monkeypatch.setenv("SS_MS_CLIENT_SECRET", "the-actual-secret-value")  # pragma: allowlist secret
    deployment(tmp_path, '[agent_watch.foundry]\nclient_secret_env = "SS_MS_CLIENT_SECRET"\n'
                         '[notifications]\nteams_webhook = "https://hook.example.com/very-secret"\n'
                         '[notifications.email]\npassword = "mail-pass"\n')
    monkeypatch.setenv("TEAMS_BOT_SECRET", "bot-secret-value")  # pragma: allowlist secret
    shown = es.describe()
    text = repr(shown)
    for secret in ("the-actual-secret-value", "bot-secret-value", "very-secret", "mail-pass"):
        assert secret not in text
    found = row("agent_watch.foundry.client_secret_env")
    assert found["value"] == "SS_MS_CLIENT_SECRET" and found["variable_set"] is True
    assert row("agent_watch.foundry.client_id_env")["variable_set"] is False
    alerts = next(s for s in shown["sections"] if s["id"] == "alerts")
    assert {r["what"]: r["set"] for r in alerts["secrets"]} == {"Teams webhook address": True, "Email password": True}
    teams = next(s for s in shown["sections"] if s["id"] == "teams")
    assert teams["secrets"] == [{"what": "Bot secret", "variable": "TEAMS_BOT_SECRET", "set": True}]


# ------------------------------------------------------------------------ layer and writes

def test_a_change_is_saved_in_the_data_folder_and_applied_over_the_deployment_file(tmp_path):
    deployment(tmp_path, "[agent_drift]\nlearning_days = 30\nsilent_hours = 12\n")
    assert row("agent_drift.learning_days")["source"] == "deployment"
    assert row("agent_drift.learning_days")["value"] == 30
    es.change("agent_drift.learning_days", 3, actor=ACTOR)
    assert es.layer_path() == tmp_path / "home" / "settings-layer.toml"
    assert (tmp_path / "config.toml").read_text(encoding="utf-8").startswith("[agent_drift]")  # untouched
    assert config.load_config()["agent_drift"] == {"learning_days": 3, "silent_hours": 12}
    shown = row("agent_drift.learning_days")
    assert shown["value"] == 3 and shown["source"] == "settings"
    assert oct(es.layer_path().stat().st_mode & 0o777) == "0o600"


def test_reset_takes_the_change_away(tmp_path):
    deployment(tmp_path, "[agent_drift]\nlearning_days = 30\n")
    es.change("agent_drift.learning_days", 3, actor=ACTOR)
    es.change("alerts.enabled", True, actor=ACTOR)
    es.reset("agent_drift.learning_days", actor=ACTOR)
    assert row("agent_drift.learning_days")["value"] == 30
    assert "agent_drift" not in es._read_layer_strict(es.layer_path())
    assert es._read_layer_strict(es.layer_path()) == {"alerts": {"enabled": True}}


def test_each_kind_round_trips_through_the_file(tmp_path):
    for setting in es.SETTINGS:
        if setting.section == "factory" and not es._installed(next(s for s in es.SECTIONS if s.id == "factory"))[0]:
            continue
        value = a_valid_value(setting)
        es.change(setting.key, value, actor=ACTOR)
    on_disk = es._read_layer_strict(es.layer_path())
    for setting in es.SETTINGS:
        found, stored = es._get_path(on_disk, setting.path)
        assert found, setting.key
        assert stored == es.validate(setting, a_valid_value(setting)), setting.key
    # And the loaded configuration carries every one of them.
    loaded = config.load_config()
    for setting in es.SETTINGS:
        found, value = es._get_path(loaded, setting.path)
        assert found and value == es.validate(setting, a_valid_value(setting)), setting.key


def test_the_environment_mapping_replaces_the_deployments_whole_table(tmp_path):
    deployment(tmp_path, '[copilot_studio_gate.environments]\n"0c6b1c52-8a6e-4f0e-9a43-6a8f2b1d9c11" = "old.crm.dynamics.com"\n')
    es.change("copilot_studio_gate.environments", {"1c6b1c52-8a6e-4f0e-9a43-6a8f2b1d9c11": "new.crm.dynamics.com"}, actor=ACTOR)
    from maverick import copilot_studio_gate
    assert copilot_studio_gate.load_settings().environments == {"1c6b1c52-8a6e-4f0e-9a43-6a8f2b1d9c11": "new.crm.dynamics.com"}
    es.reset("copilot_studio_gate.environments", actor=ACTOR)
    assert list(copilot_studio_gate.load_settings().environments.values()) == ["old.crm.dynamics.com"]


def test_hand_edited_layer_cannot_do_more_than_the_page_can(tmp_path):
    es.layer_path().parent.mkdir(parents=True)
    es.layer_path().write_text(
        '[alerts]\nenabled = "yes please"\n[providers.anthropic]\napi_key = "x"\n[approval]\nseparate_approver = "never"\n'
        '[notifications]\nteams_webhook = "https://evil.example.com/x"\n[settings]\nlocked = []\n', encoding="utf-8")
    config.reset_config_cache()
    cfg = config.load_config()
    assert "providers" not in cfg and "teams_webhook" not in cfg.get("notifications", {})
    assert "alerts" not in cfg or "enabled" not in cfg["alerts"]  # the wrong type is ignored
    assert cfg["approval"]["separate_approver"] == "never"        # a listed, valid value applies
    assert "settings" not in cfg


# --------------------------------------------------------------------------------- locks

def test_an_environment_variable_locks_a_setting(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    shown = row("alerts.enabled")
    assert shown["locked"] and shown["source"] == "environment" and shown["value"] is True
    assert "MAVERICK_ALERTS" in shown["source_text"]
    with pytest.raises(SettingRefused) as refused:
        es.change("alerts.enabled", False, actor=ACTOR)
    assert refused.value.status == 409 and "Change it there" in str(refused.value)
    with pytest.raises(SettingRefused):
        es.reset("alerts.enabled", actor=ACTOR)
    assert not es.layer_path().exists()


def test_a_saved_value_does_not_beat_an_environment_variable_set_later(monkeypatch):
    es.change("alerts.enabled", False, actor=ACTOR)
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    from maverick import ops_alert
    assert ops_alert.alerts_enabled() is True
    assert row("alerts.enabled")["value"] is True


def test_the_deployment_can_lock_a_setting_by_name(tmp_path):
    deployment(tmp_path, '[settings]\nlocked = ["agent_drift.learning_days"]\n[agent_drift]\nlearning_days = 21\n')
    shown = row("agent_drift.learning_days")
    assert shown["locked"] and shown["source"] == "deployment" and shown["value"] == 21
    assert shown["source_text"] == "Set by the deployment. Change it there."
    with pytest.raises(SettingRefused) as refused:
        es.change("agent_drift.learning_days", 1, actor=ACTOR)
    assert refused.value.status == 409
    es.change("agent_drift.silent_hours", 5, actor=ACTOR)  # others stay editable


def test_a_value_saved_before_the_deployment_locked_it_stops_applying(tmp_path):
    es.change("agent_drift.learning_days", 3, actor=ACTOR)
    assert config.load_config()["agent_drift"]["learning_days"] == 3
    deployment(tmp_path, '[settings]\nlocked = ["agent_drift.learning_days"]\n[agent_drift]\nlearning_days = 21\n')
    assert config.load_config()["agent_drift"]["learning_days"] == 21
    from maverick import agent_drift
    assert agent_drift.settings()["learning_days"] == 21


def test_a_malformed_lock_list_locks_everything(tmp_path):
    deployment(tmp_path, '[settings]\nlocked = "agent_drift.learning_days"\n')
    assert all(row(s.key)["locked"] for s in es.SETTINGS if s.section in ("drift", "alerts") and not es.env_lock(s))
    with pytest.raises(SettingRefused):
        es.change("agent_drift.silent_hours", 5, actor=ACTOR)


def test_the_operator_overlay_wins_so_its_settings_are_shown_locked(tmp_path, monkeypatch):
    overlay = tmp_path / "operator.toml"
    overlay.write_text('[agent_drift]\nlearning_days = 9\n', encoding="utf-8")
    monkeypatch.setenv(config.CONFIG_OVERLAY_ENV, str(overlay))
    config.reset_config_cache()
    assert row("agent_drift.learning_days")["locked"] is True
    assert config.load_config()["agent_drift"]["learning_days"] == 9


# ------------------------------------------------------------------- takes effect per call

def test_alerts_follow_a_change_without_a_restart(tmp_path):
    from maverick import ops_alert
    assert ops_alert.alerts_enabled() is False
    es.change("alerts.enabled", True, actor=ACTOR)
    assert ops_alert.alerts_enabled() is True
    es.change("alerts.backends", ["teams", "email"], actor=ACTOR)
    assert ops_alert._channels()[0] == ["teams", "email"]
    assert row("alerts.backends")["value"] == ["teams", "email"]
    es.change("alerts.backends", [], actor=ACTOR)  # nowhere, written as the documented ["none"]
    assert ops_alert._channels() == ([], [])
    assert es._read_layer_strict(es.layer_path())["alerts"]["backends"] == ["none"]
    assert row("alerts.backends")["value"] == []
    es.change("alerts.enabled", False, actor=ACTOR)
    assert ops_alert.alerts_enabled() is False


def test_the_second_person_rule_follows_a_change(tmp_path):
    from maverick.safety import dual_control
    assert dual_control.separate_approver_mode() == "always"
    es.change("approval.separate_approver", "never", actor=ACTOR)
    assert dual_control.separate_approver_mode() == "never"
    es.change("approval.separate_approver", "when_available", actor=ACTOR)
    assert dual_control.separate_approver_mode() == "when_available"


def test_reminders_and_request_detail_follow_a_change():
    from maverick import expiry_reminders
    es.change("approval.reminder_fraction_left", 0.5, actor=ACTOR)
    assert expiry_reminders.reminder_fraction() == 0.5
    es.change("agent_keys.expiry_warning_days", 3, actor=ACTOR)
    assert expiry_reminders.key_warning_days() == 3
    from maverick.config import get_external_agents
    es.change("external_agents.show_request_detail", False, actor=ACTOR)
    assert get_external_agents()["show_request_detail"] is False


def test_drift_thresholds_follow_a_change():
    from maverick import agent_drift
    es.change("agent_drift.learning_days", 2, actor=ACTOR)
    es.change("agent_drift.volume_ratio", 5.5, actor=ACTOR)
    es.change("agent_drift.on_drift", "contain", actor=ACTOR)
    es.change("agent_drift.silent_hours", 24, actor=ACTOR)
    es.change("agent_drift.enable", False, actor=ACTOR)
    found = agent_drift.settings()
    assert (found["learning_days"], found["volume_ratio"], found["on_drift"], found["silent_hours"],
            found["enable"]) == (2, 5.5, "contain", 24, False)


def test_the_rest_follow_a_change_too():
    from maverick import agent_watch, copilot_studio_gate, entra_directory, model_drift
    from maverick.approval_notify import teams_settings
    from maverick.config import get_ekko
    es.change("agent_watch.enable", True, actor=ACTOR)
    es.change("agent_watch.platforms", ["foundry", "workday"], actor=ACTOR)
    es.change("agent_watch.sync_minutes", 30, actor=ACTOR)
    assert agent_watch.settings()["platforms"] == ["foundry", "workday"] and agent_watch.settings()["sync_minutes"] == 30
    es.change("agent_watch.foundry.client_id_env", "SS_CLIENT", actor=ACTOR)
    assert config.load_config()["agent_watch"]["foundry"]["client_id_env"] == "SS_CLIENT"
    es.change("teams.enabled", True, actor=ACTOR)
    es.change("teams.app_id", "11111111-2222-3333-4444-555555555555", actor=ACTOR)
    es.change("teams.app_secret_env", "MY_BOT_SECRET", actor=ACTOR)
    assert teams_settings()["enabled"] and teams_settings()["app_secret_env"] == "MY_BOT_SECRET"
    es.change("copilot_studio_gate.on_error", "allow", actor=ACTOR)
    es.change("copilot_studio_gate.unenrolled", "block", actor=ACTOR)
    gate = copilot_studio_gate.load_settings()
    assert (gate.on_error, gate.unenrolled) == ("allow", "block")
    es.change("entra_directory.cache_minutes", 20, actor=ACTOR)
    assert entra_directory.settings()["cache_minutes"] == 20
    es.change("ekko.retention_days", 7, actor=ACTOR)
    es.change("ekko.allowed_apps", ["excel", "word"], actor=ACTOR)
    assert get_ekko()["retention_days"] == 7 and get_ekko()["allowed_apps"] == ["excel", "word"]
    es.change("model_drift.psi_threshold", 0.4, actor=ACTOR)
    assert model_drift.settings()["psi_threshold"] == 0.4


def test_factory_settings_follow_a_change():
    from maverick.factory import settings as factory
    es.change("factory.provider", "foundry_openai", actor=ACTOR)
    es.change("factory.deployment", "gpt-4o", actor=ACTOR)
    es.change("factory.max_test_cases", 7, actor=ACTOR)
    loaded = factory.load()
    assert (loaded.provider, loaded.deployment, loaded.max_test_cases) == ("foundry_openai", "gpt-4o", 7)


def test_what_the_page_shows_is_what_the_features_use(tmp_path):
    """The effective value shown for each setting equals what the feature itself reads, after a change and before."""
    from maverick import agent_drift, copilot_studio_gate, model_drift
    deployment(tmp_path, "[agent_drift]\nvolume_ratio = 500\n[model_drift]\nbins = 1\n")
    assert row("agent_drift.volume_ratio")["value"] == agent_drift.settings()["volume_ratio"] == 100.0   # clamped
    assert row("model_drift.bins")["value"] == model_drift.settings()["bins"] == 2
    assert row("copilot_studio_gate.on_error")["value"] == copilot_studio_gate.load_settings().on_error == "block"
    assert row("agent_drift.window_days")["value"] == agent_drift.settings()["window_days"]


# --------------------------------------------------------------------------- fail closed

@pytest.mark.parametrize("damage", [b"[alerts\nenabled = true", b"\xff\xfe\x00not utf8", b"= = ="])
def test_an_unreadable_layer_is_held_whole_and_reported_like_an_unreadable_file(tmp_path, damage):
    es.change("alerts.enabled", True, actor=ACTOR)
    es.layer_path().write_bytes(damage)
    config.reset_config_cache()
    assert config.load_config().get("alerts", {}).get("enabled") is not True       # nothing from it applies
    assert str(es.layer_path()) in config.config_source_errors()                     # health and callers see it
    assert str(es.layer_path()) in config.config_source_errors(include_tenant=False)
    assert es.layer_problem()
    from maverick import copilot_studio_gate
    assert copilot_studio_gate.load_settings().unreadable is True                    # a caller that fails closed does
    with pytest.raises(SettingRefused) as refused:
        es.change("alerts.enabled", False, actor=ACTOR)
    assert refused.value.status == 503
    with pytest.raises(SettingRefused):
        es.reset("alerts.enabled", actor=ACTOR)
    assert es.layer_path().read_bytes() == damage                                    # never written over


def test_a_layer_that_cannot_be_opened_is_reported(tmp_path):
    es.change("alerts.enabled", True, actor=ACTOR)
    es.layer_path().chmod(0)
    if os.access(es.layer_path(), os.R_OK):
        es.layer_path().chmod(0o600)
        pytest.skip("this account can read any file")
    try:
        config.reset_config_cache()
        assert config.load_config().get("alerts", {}).get("enabled") is not True
        assert str(es.layer_path()) in config.config_source_errors()
        with pytest.raises(SettingRefused):
            es.change("alerts.enabled", False, actor=ACTOR)
    finally:
        es.layer_path().chmod(0o600)


def test_a_layer_that_is_repaired_applies_again(tmp_path):
    es.change("alerts.enabled", True, actor=ACTOR)
    good = es.layer_path().read_bytes()
    es.layer_path().write_bytes(b"[alerts")
    config.reset_config_cache()
    config.load_config()
    assert str(es.layer_path()) in config.config_source_errors()
    es.layer_path().write_bytes(good)
    config.reset_config_cache()
    config.load_config()
    assert not config.config_source_errors()
    assert config.load_config()["alerts"]["enabled"] is True


def test_an_audit_log_that_refuses_stops_the_change(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit.errors import AuditRefused

    def refuse(kind, **payload):
        raise AuditRefused("no")
    monkeypatch.setattr(audit_pkg, "record", refuse)
    with pytest.raises(AuditRefused):
        es.change("alerts.enabled", True, actor=ACTOR)
    assert not es.layer_path().exists()
    monkeypatch.setattr(audit_pkg, "record", lambda kind, **payload: False)
    with pytest.raises(SettingRefused) as refused:
        es.change("alerts.enabled", True, actor=ACTOR)
    assert refused.value.status == 503 and not es.layer_path().exists()


def test_a_failed_write_says_so_and_leaves_the_layer_as_it_was(monkeypatch, audit):
    es.change("alerts.enabled", True, actor=ACTOR)
    before = es.layer_path().read_bytes()

    def broken(path, text, **kwargs):
        raise OSError("disk full")
    import maverick.file_lock as file_lock
    monkeypatch.setattr(file_lock, "atomic_write_text", broken)
    with pytest.raises(SettingRefused) as refused:
        es.change("agent_drift.learning_days", 4, actor=ACTOR)
    assert refused.value.status == 503
    assert es.layer_path().read_bytes() == before
    assert audit[-1]["kind"] == "setting_change_failed"


def test_two_changes_at_once_both_land(tmp_path):
    import threading
    keys = [("agent_drift.silent_hours", 7), ("agent_drift.min_runs", 9), ("agent_drift.check_minutes", 20),
            ("alerts.enabled", True), ("keys_x", None)]
    errors: list[Exception] = []

    def go(key, value):
        try:
            es.change(key, value, actor=ACTOR)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    threads = [threading.Thread(target=go, args=item) for item in keys[:4]]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    loaded = config.load_config()
    assert loaded["agent_drift"]["silent_hours"] == 7 and loaded["agent_drift"]["min_runs"] == 9
    assert loaded["agent_drift"]["check_minutes"] == 20 and loaded["alerts"]["enabled"] is True


# ------------------------------------------------------------------------------- audit

def test_every_change_and_reset_is_audited_with_old_and_new_values(tmp_path, audit):
    deployment(tmp_path, "[agent_drift]\nlearning_days = 30\n")
    es.change("agent_drift.learning_days", 3, actor=ACTOR)
    es.change("alerts.enabled", True, actor=ACTOR)
    es.change("agent_watch.foundry.client_secret_env", "SS_MS_CLIENT_SECRET", actor=ACTOR)
    es.reset("agent_drift.learning_days", actor=ACTOR)
    changes = [r for r in audit if r["kind"] == "setting_changed"]
    assert [(r["setting"], r["old"], r["new"], r["actor"], r["reset"]) for r in changes] == [
        ("agent_drift.learning_days", 30, 3, ACTOR, False),
        ("alerts.enabled", False, True, ACTOR, False),
        ("agent_watch.foundry.client_secret_env", "", "SS_MS_CLIENT_SECRET", ACTOR, False),
        ("agent_drift.learning_days", 3, None, ACTOR, True),
    ]
    assert all(r["agent"] == "settings" if "agent" in r else True for r in changes)


def test_a_refused_change_is_not_audited(audit):
    with pytest.raises(SettingRefused):
        es.change("agent_drift.learning_days", 9999, actor=ACTOR)
    with pytest.raises(SettingRefused):
        es.change("nonsense", 1, actor=ACTOR)
    assert not [r for r in audit if r["kind"].startswith("setting_")]


def test_the_audit_entry_holds_no_secret(monkeypatch, audit):
    monkeypatch.setenv("SS_MS_CLIENT_SECRET", "the-actual-secret-value")  # pragma: allowlist secret
    es.change("agent_watch.foundry.client_secret_env", "SS_MS_CLIENT_SECRET", actor=ACTOR)
    assert "the-actual-secret-value" not in repr(audit)


# ------------------------------------------------------------------------ not installed

def test_a_section_whose_feature_is_not_installed_says_so(monkeypatch):
    import maverick.factory as factory
    monkeypatch.setattr(factory, "runtime_available", lambda: False)
    section = next(s for s in es.describe()["sections"] if s["id"] == "factory")
    assert section["installed"] is False and section["settings"] == [] and "not installed" in section["not_installed"]
    with pytest.raises(SettingRefused) as refused:
        es.change("factory.max_test_cases", 5, actor=ACTOR)
    assert refused.value.status == 409
