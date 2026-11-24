"""The Settings page and its API: who may open and change, the same-origin check, confirmation, locked
settings, secrets, escaping, and that a change reaches the rest of the product without a restart.

Hermetic. Each person signs in as in ``signin_kit``; every answer comes from the real routes."""
from __future__ import annotations

import json

import markupsafe
import pytest
from fastapi.testclient import TestClient

from tests.new import signin_kit as kit
from tests.new.signin_kit import ROLES

API = "/api/v1/settings"


@pytest.fixture(scope="module")
def signing_key():
    return kit.new_key()


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch, request, signing_key):
    from maverick import governed_records

    governed_records._reset_process_authority_pin_for_testing()
    stop = kit.start(tmp_path, monkeypatch, request, signing_key)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_REPLICA_COUNT",
                 "MAVERICK_WORLD_BACKEND", "MAVERICK_AGENT_DRIFT", "MAVERICK_AGENT_WATCH", "MAVERICK_EKKO",
                 "MAVERICK_ENTRA_DIRECTORY"):
        monkeypatch.delenv(name, raising=False)
    yield tmp_path
    governed_records._reset_process_authority_pin_for_testing()
    stop()


@pytest.fixture
def app():
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def person(app, signing_key):
    def client(role: str) -> TestClient:
        return kit.client_for(app, signing_key, role)
    return client


def deployment(tmp_path, body: str) -> None:
    kit.configure(tmp_path, body)


def audit_rows(tmp_path) -> list[dict]:
    """The settings entries in this test's audit folder, as written."""
    rows = []
    for path in sorted((tmp_path / "audit").glob("*.ndjson")):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line) if line.strip() else {}
            if str(row.get("kind", "")).startswith("setting_"):
                rows.append(row)
    return rows


# ---------------------------------------------------------------- permissions

@pytest.mark.parametrize("role", [r for r in ROLES if r != "admin"])
def test_only_an_administrator_sees_or_changes_settings(person, role):
    who = person(role)
    assert who.get("/settings").status_code == 403
    assert who.get(API).status_code == 403
    assert who.post(f"{API}/alerts.enabled", json={"value": True, "confirmed": True}).status_code == 403
    assert who.post(f"{API}/alerts.enabled/reset", json={"confirmed": True}).status_code == 403
    assert person("admin").get(API).json()  # and nothing was changed
    row = next(s for sec in person("admin").get(API).json()["sections"] for s in sec["settings"] if s["key"] == "alerts.enabled")
    assert row["source"] == "default"


def test_the_page_is_not_offered_in_the_sidebar_to_anyone_but_administrators(person):
    for role in ROLES:
        page = person(role).get("/")
        assert page.status_code == 200
        assert ('href="/settings"' in page.text) == (role == "admin"), role


def test_the_page_registry_says_admin_only():
    from maverick_dashboard import ui_visibility

    page = next(p for p in ui_visibility.PAGES if p["path"] == "/settings")
    assert page["floor"] == "admin" and page["default"] == "admin"
    assert ("/settings", "admin") in ui_visibility.LOCKED


# ----------------------------------------------------------------- rendering

def test_every_section_renders_its_settings_with_value_and_source(person, installation):
    deployment(installation, "[agent_drift]\nlearning_days = 30\n")
    page = person("admin").get("/settings")
    assert page.status_code == 200 and "private, no-store" in page.headers["cache-control"]
    for title in ("Alerts", "Approvals", "Drift", "Platform checks", "Teams", "Copilot Studio gate", "Entra directory",
                  "Ekko", "Agent factory", "Access keys", "Models"):
        assert f">{title}</h2>" in page.text, title
    from maverick import editable_settings as es
    for setting in es.SETTINGS:
        assert f'data-key="{setting.key}"' in page.text, setting.key
        assert str(markupsafe.escape(setting.label)) in page.text, setting.label
    assert "From the settings file" in page.text and "Default" in page.text
    assert 'value="30"' in page.text
    assert "Send a test alert" in page.text and "Send a test Teams card" in page.text and "Run a platform check now" in page.text
    assert page.text.count("Second Shift") > 3 and "Lightwork" not in page.text and "Maverick" not in page.text


def test_the_api_lists_the_same_settings(person, installation):
    shown = person("admin").get(API).json()
    assert [s["id"] for s in shown["sections"]][0] == "alerts"
    keys = [r["key"] for s in shown["sections"] for r in s["settings"]]
    from maverick import editable_settings as es
    assert keys == [s.key for s in es.SETTINGS if True] or set(keys) == {s.key for s in es.SETTINGS}
    assert shown["layer_problem"] == ""
    assert "settings-layer.toml" == shown["layer_file"]


def test_secrets_never_appear_only_whether_a_variable_is_set(person, installation, monkeypatch):
    monkeypatch.setenv("SS_MS_CLIENT_SECRET", "the-actual-secret-value")  # pragma: allowlist secret
    monkeypatch.setenv("TEAMS_BOT_SECRET", "bot-secret-value")  # pragma: allowlist secret
    deployment(installation, '[agent_watch.foundry]\nclient_secret_env = "SS_MS_CLIENT_SECRET"\n'
                             '[notifications]\nteams_webhook = "https://hook.example.com/very-secret"\n'
                             '[notifications.email]\npassword = "mail-pass"\n')
    admin = person("admin")
    for body in (admin.get("/settings").text, admin.get(API).text):
        for secret in ("the-actual-secret-value", "bot-secret-value", "very-secret", "mail-pass", "hook.example.com"):
            assert secret not in body
    assert "SS_MS_CLIENT_SECRET" in admin.get("/settings").text
    assert "Yes, set" in admin.get("/settings").text and "That variable is not set." in admin.get("/settings").text


def test_what_is_typed_in_a_setting_is_escaped(person, installation):
    deployment(installation, '[teams]\nchannel_id = "<script>alert(1)</script>"\n[factory]\ndeployment = "<img src=x onerror=alert(1)>"\n')
    page = person("admin").get("/settings").text
    assert "<script>alert(1)</script>" not in page and "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_a_section_whose_feature_is_missing_says_so(person, monkeypatch):
    import maverick.factory as factory
    monkeypatch.setattr(factory, "runtime_available", lambda: False)
    page = person("admin").get("/settings").text
    assert "Not installed" in page
    assert 'data-key="factory.max_test_cases"' not in page
    changed = person("admin").post(f"{API}/factory.max_test_cases", json={"value": 5, "confirmed": True})
    assert changed.status_code == 409 and "not installed" in changed.json()["detail"]


# ------------------------------------------------------------------- changes

def test_a_change_is_confirmed_saved_audited_and_applied_without_a_restart(person, installation):
    admin = person("admin")
    made = admin.post(f"{API}/agent_drift.learning_days", json={"value": 3, "confirmed": True})
    assert made.status_code == 200, made.text
    assert made.json()["value"] == 3 and made.json()["source"] == "settings"
    from maverick import agent_drift
    assert agent_drift.settings()["learning_days"] == 3
    rows = audit_rows(installation)
    assert len(rows) == 1
    payload = rows[0].get("payload", rows[0])
    assert payload["setting"] == "agent_drift.learning_days" and payload["old"] == 14 and payload["new"] == 3
    assert "user:admin" in str(payload["actor"])
    again = admin.post(f"{API}/agent_drift.learning_days/reset", json={"confirmed": True})
    assert again.status_code == 200 and again.json()["value"] == 14 and again.json()["source"] == "default"
    assert agent_drift.settings()["learning_days"] == 14
    assert len(audit_rows(installation)) == 2


def test_the_home_page_warning_follows_the_alerts_setting(person, installation):
    admin = person("admin")
    before = admin.get("/").text
    assert admin.post(f"{API}/alerts.enabled", json={"value": True, "confirmed": True}).status_code == 200
    assert admin.get("/").text != before
    assert admin.post(f"{API}/alerts.enabled/reset", json={"confirmed": True}).status_code == 200


def test_the_second_person_rule_changes_for_the_next_request(person):
    from maverick.safety import dual_control
    assert dual_control.separate_approver_mode() == "always"
    assert person("admin").post(f"{API}/approval.separate_approver", json={"value": "never", "confirmed": True}).status_code == 200
    assert dual_control.separate_approver_mode() == "never"


def test_a_change_needs_the_confirmation(person):
    admin = person("admin")
    for body in ({"value": True}, {"value": True, "confirmed": False}, {"value": True, "confirmed": "yes"},
                 {"confirmed": True}, {"value": True, "confirmed": True, "extra": 1}):
        assert admin.post(f"{API}/alerts.enabled", json=body).status_code == 422, body
    assert admin.post(f"{API}/alerts.enabled/reset", json={}).status_code == 422


def test_refused_values_unknown_keys_and_secrets(person, installation):
    admin = person("admin")
    assert admin.post(f"{API}/agent_drift.learning_days", json={"value": 9999, "confirmed": True}).status_code == 422
    assert admin.post(f"{API}/agent_drift.learning_days", json={"value": "3", "confirmed": True}).status_code == 422
    assert admin.post(f"{API}/alerts.enabled", json={"value": "true", "confirmed": True}).status_code == 422
    unknown = admin.post(f"{API}/providers.anthropic.api_key", json={"value": "sk-x", "confirmed": True})
    assert unknown.status_code == 404
    secret = admin.post(f"{API}/agent_watch.foundry.client_secret_env", json={"value": "abc123SecretValue", "confirmed": True})
    assert secret.status_code == 422 and "abc123SecretValue" not in secret.text
    assert not audit_rows(installation)


def test_a_locked_setting_cannot_be_changed(person, installation, monkeypatch):
    deployment(installation, '[settings]\nlocked = ["agent_drift.learning_days"]\n[agent_drift]\nlearning_days = 21\n')
    admin = person("admin")
    refused = admin.post(f"{API}/agent_drift.learning_days", json={"value": 1, "confirmed": True})
    assert refused.status_code == 409 and "Change it there" in refused.json()["detail"]
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    assert admin.post(f"{API}/alerts.enabled", json={"value": False, "confirmed": True}).status_code == 409
    page = admin.get("/settings").text
    assert "Set by the deployment" in page and "MAVERICK_ALERTS" in page
    from maverick import agent_drift
    assert agent_drift.settings()["learning_days"] == 21


def test_an_unreadable_layer_fails_closed_like_an_unreadable_settings_file(person, installation):
    admin = person("admin")
    assert admin.post(f"{API}/alerts.enabled", json={"value": True, "confirmed": True}).status_code == 200
    from maverick import editable_settings as es
    es.layer_path().write_bytes(b"[alerts")
    # The sign-in check refuses everyone while any settings source cannot be read, as it does for the file.
    refused = admin.post(f"{API}/alerts.enabled", json={"value": False, "confirmed": True})
    assert refused.status_code >= 400
    assert admin.get("/settings").status_code >= 400
    assert es.layer_path().read_bytes() == b"[alerts"
    with pytest.raises(es.SettingRefused) as direct:
        es.change("alerts.enabled", False, actor="user:admin")
    assert direct.value.status == 503


def test_an_audit_log_that_cannot_take_the_entry_stops_the_change(person, monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit.errors import AuditRefused

    def refuse(kind, **payload):
        if kind == "setting_changed":
            raise AuditRefused("no")
        return True
    monkeypatch.setattr(audit_pkg, "record", refuse)
    answer = person("admin").post(f"{API}/alerts.enabled", json={"value": True, "confirmed": True})
    assert answer.status_code == 503 and "audit log" in answer.json()["detail"]
    from maverick import editable_settings as es
    assert not es.layer_path().exists()


# ------------------------------------------------------------- same-origin

def test_a_change_from_another_site_is_refused(app, signing_key, installation):
    token = kit.mint(signing_key, "admin")
    for headers in ({"Origin": "https://evil.example.com"}, {}, {"Referer": "https://evil.example.com/x"}):
        foreign = TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + token, **headers})
        assert foreign.post(f"{API}/alerts.enabled", json={"value": True, "confirmed": True}).status_code == 403, headers
        assert foreign.post(f"{API}/alerts.enabled/reset", json={"confirmed": True}).status_code == 403, headers
    same = TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1"})
    assert same.post(f"{API}/alerts.enabled", json={"value": True, "confirmed": True}).status_code == 200
    from maverick import ops_alert
    assert ops_alert.alerts_enabled() is True


# ------------------------------------------------------------ test buttons

def test_the_test_buttons_call_the_existing_endpoints(person):
    from maverick import editable_settings as es

    posted = {url for section in es.SECTIONS for _label, url, _what in section.tests}
    assert posted == {"/api/v1/alerts/test", "/api/v1/teams/test", "/api/v1/agent-watch/sync"}
    admin = person("admin")
    page = admin.get("/settings").text
    for url in posted:
        assert f'data-settings-test="{url}"' in page
    assert admin.post("/api/v1/alerts/test").status_code == 200
    assert person("viewer").post("/api/v1/alerts/test").status_code == 403


def test_the_page_script_uses_the_shared_helpers_and_confirms(person):
    page = person("admin").get("/settings").text
    assert "window.mvConfirm" in page and "window.mvFetchJSON" in page and "confirmed: true" in page
