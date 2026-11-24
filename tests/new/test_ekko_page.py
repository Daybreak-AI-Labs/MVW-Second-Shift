"""The Ekko page: what one person is shown about their own consent, recorder and recordings."""
from __future__ import annotations

import hashlib
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

INSTRUCTIONS = "/api/v1/external/ekko/instructions"
HANDOVER = "/api/v1/external/ekko/handover"


@pytest.fixture
def settings(tmp_path, monkeypatch, request):
    """One installation with its own data folder and settings file; returns the writer."""
    from maverick import config, world_model
    from maverick.audit import signing
    from maverick_dashboard import ekko_handover_api as handover

    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"ekko-page-test:{request.node.nodeid}".encode()
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    signing._reset_injected_keypair_cache()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_EKKO", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_TENANT", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")

    def write(text: str) -> None:
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()

    write('[ekko]\nenable = true\nallowed_apps = ["excel", "powerpoint"]\nretention_days = 21\nenrollment_days = 60\n')
    handover._rate_times.clear()
    handover._lease_renewed.clear()
    yield write
    signing._reset_injected_keypair_cache()
    config.reset_config_cache()


@pytest.fixture
def person(settings):
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield client


def _page(person, device="desk") -> str:
    page = person.get(f"/ekko?device={device}")
    assert page.status_code == 200, page.text
    assert page.headers["cache-control"] == "private, no-store"
    return page.text.split('<h1 class="page-title">', 1)[1]


def _shown(page: str) -> str:
    """The page as markup, without its script."""
    return page.split("<script", 1)[0]


def _enroll(person, device="desk", apps=("excel", "powerpoint")) -> None:
    enrolled = person.post("/api/v1/ekko/enroll", json={
        "device_id": device, "apps": list(apps), "days": 14, "acknowledge_capture_scope": True})
    assert enrolled.status_code == 200, enrolled.text


def _key(person, device="desk") -> str:
    created = person.post("/api/v1/ekko/device-key", json={"device_id": device})
    assert created.status_code == 201, created.text
    return created.json()["device_key"]


def _start(person, device="desk") -> str:
    started = person.post("/api/v1/ekko/sessions", json={"device_id": device, "acknowledge_capture_scope": True})
    assert started.status_code == 201, started.text
    return started.json()["session"]["session_id"]


# --- before consent ---------------------------------------------------------------

def test_what_is_recorded_is_said_before_consent_is_asked(person):
    page = _shown(_page(person))
    assert "It records" in page and "the name of the app in front" in page
    for never in ("window titles", "what is on your screen", "what you type", "the clipboard", "web addresses",
                  "file names", "anything inside a file"):
        assert never in page.split("It never records", 1)[1].split("</p>", 1)[0]
    assert "Nothing is recorded until you press Start" in page
    assert "deleted after 21 days" in page
    assert "no view across people" in page
    # The explanation comes first, then the form that asks.
    assert page.index("It never records") < page.index('id="ekko-enroll"')


def test_a_person_without_an_enrolled_device_is_offered_consent_and_nothing_else(person):
    page = _shown(_page(person))
    assert "You have not given consent for this computer" in page
    assert 'value="excel" checked> Microsoft Excel' in page and 'value="powerpoint" checked> Microsoft PowerPoint' in page
    assert '<option value="60" selected>60 days</option>' in page
    assert re.search(r'name="consent" required>\s*I have read what Ekko records and never records', page)
    assert "Enrolling does not start recording" in page
    for absent in ('id="ekko-recorder"', 'id="ekko-recording"', 'data-ekko="start"', 'data-ekko="key"', "Consent given"):
        assert absent not in page
    assert "Nothing has been recorded on this computer" in page
    # Visiting the page enrolls nothing and creates nothing.
    status = person.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["enrollment"] is None and status["session"] is None


def test_the_page_says_when_ekko_is_off(person, settings):
    settings('[ekko]\nenable = false\nallowed_apps = ["excel"]\n')
    page = _shown(_page(person))
    assert "Ekko is turned off" in page and "Nothing is recorded while it is off" in page
    assert 'id="ekko-enroll"' not in page and 'data-ekko="start"' not in page
    assert "It never records" in page                    # still explained
    assert 'data-ekko="erase-all"' in page               # and what was recorded can still be erased


def test_the_page_says_when_no_app_is_allowed(person, settings):
    settings("[ekko]\nenable = true\nallowed_apps = []\n")
    page = _shown(_page(person))
    assert "No apps are allowed yet" in page and 'id="ekko-enroll"' not in page


# --- with an enrolled device --------------------------------------------------------

def test_an_enrolled_device_shows_consent_the_recorder_and_recording(person):
    _enroll(person, apps=("excel",))
    page = _shown(_page(person))
    assert "Consent given" in page and 'id="ekko-enroll"' not in page
    assert '<span class="badge">Microsoft Excel</span>' in page and "Microsoft PowerPoint" not in page
    assert "No recorder key yet" in page and "Create a recorder key" in page
    assert "Recording has not started" in page and 'data-ekko="start"' in page
    assert 'data-ekko="withdraw"' in page and 'data-ekko="forget"' in page
    assert "Only you start recording" in page


def test_the_page_follows_the_key_the_recorder_and_the_session(person):
    _enroll(person)
    key = _key(person)
    page = _shown(_page(person))
    assert "Recorder not heard from yet" in page and "Replace the recorder key" in page and 'data-ekko="key-remove"' in page

    recorder = TestClient(person.app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {key}"})
    assert recorder.get(INSTRUCTIONS).status_code == 200
    assert "Recorder connected" in _shown(_page(person))

    session = _start(person)
    handed = recorder.post(HANDOVER, json={"session_id": session, "batch_id": "batch-0001", "account": "a" * 64, "activities": [
        {"app": "excel", "action": "switch", "occurred_at": time.time()},
        {"app": "powerpoint", "action": "switch", "occurred_at": time.time()}]})
    assert handed.json()["accepted"] == 2
    page = _shown(_page(person))
    assert "Recording is on" in page and '<span id="ekko-count">2</span> activities noticed' in page
    assert 'data-ekko="pause"' in page and 'data-ekko="stop"' in page and 'data-ekko="start"' not in page
    assert f'data-ekko="erase-session" data-id="{session}"' in page and "2 activities" in page
    assert f'data-session="{session}"' in page

    assert person.post(f"/api/v1/ekko/sessions/{session}/pause", json={"device_id": "desk"}).status_code == 200
    page = _shown(_page(person))
    assert "Recording is paused" in page and 'data-ekko="resume"' in page and 'data-ekko="pause"' not in page
    assert person.post(f"/api/v1/ekko/sessions/{session}/stop", json={"device_id": "desk"}).status_code == 200
    page = _shown(_page(person))
    assert "Recording is stopped" in page and 'data-ekko="start"' in page

    # The key was shown once, when it was created: no page carries it or its hash.
    from maverick import ekko_device_keys as keys

    whole = person.get("/ekko?device=desk").text
    assert key not in whole and key[21:] not in whole and keys.hash_key(key)[7:] not in whole


def test_a_recorder_that_has_gone_quiet_is_said_to_be_quiet(person, monkeypatch):
    from maverick_dashboard import ekko_handover_api as handover

    _enroll(person)
    recorder = TestClient(person.app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {_key(person)}"})
    assert recorder.get(INSTRUCTIONS).status_code == 200
    later = time.time() + 600
    monkeypatch.setattr(handover, "_now", lambda: later)
    assert "Recorder not heard from recently" in _shown(_page(person))


def test_a_key_record_that_cannot_be_read_is_said_so_and_can_be_removed(person, tmp_path):
    import sqlite3

    _enroll(person)
    _key(person)
    with sqlite3.connect(tmp_path / "ekko" / "device-keys.sqlite3") as index:
        index.execute("UPDATE ekko_device_keys SET record = ?", (b"damaged",))
    page = _shown(_page(person))
    assert "The recorder key cannot be read" in page and "Nothing is accepted from the recorder" in page
    assert 'data-ekko="key-remove"' in page and "Recorder connected" not in page
    assert person.delete("/api/v1/ekko/device-key?device_id=desk").json() == {"removed": True}
    assert "No recorder key yet" in _shown(_page(person))


def test_suggestions_carry_the_wording_about_what_they_are(person):
    page = _shown(_page(person))
    panel = page.split('id="ekko-suggestions"', 1)[1].split("</div>", 1)[0]
    assert "These are patterns to investigate." in panel
    assert "This is never an employee performance score." in panel
    assert "Look for repeated work" in page
    script = person.get("/ekko?device=desk").text.split("<script nonce=", 1)[1]
    assert "/api/v1/ekko/candidates/mine" in script
    assert "opportunity_score" not in script and "confidence" not in script  # no number that reads as a rating
    assert "innerHTML" not in script  # what the server returns is written as text


def test_the_page_offers_every_way_to_take_data_and_consent_back(person):
    _enroll(person)
    _key(person)
    _start(person)
    whole = person.get("/ekko?device=desk").text
    page, script = _shown(whole), whole.split("<script nonce=", 1)[1]
    for control in ("erase-session", "erase-all", "forget", "withdraw", "key-remove", "pause", "stop"):
        assert f'data-ekko="{control}"' in page, control
    for call in ('"/api/v1/ekko/revoke"', '"/api/v1/ekko/data"', '"/api/v1/ekko/device"', '"/api/v1/ekko/device-key"',
                 '"/api/v1/ekko/enroll"', '"/api/v1/ekko/sessions"'):
        assert call in script, call
    assert "Erasing cannot be undone" in page


def test_other_devices_with_a_key_are_listed_for_the_same_person_only(person, monkeypatch):
    from maverick_dashboard import ekko_routes as ekko

    _enroll(person, "desk")
    _key(person, "desk")
    _enroll(person, "laptop-2")
    _key(person, "laptop-2")
    page = _shown(_page(person, "desk"))
    assert '<a href="/ekko?device=laptop-2">laptop-2</a>' in page
    assert '<a href="/ekko?device=desk">' not in page

    monkeypatch.setattr(ekko, "_owner", lambda request: "user:someone-else")
    other = _shown(_page(person, "desk"))
    assert "laptop-2" not in other and "You have not given consent" in other and "Consent given" not in other
    assert '<span id="ekko-count">' not in other and "Nothing has been recorded on this computer" in other


# --- what the page will not do ---------------------------------------------------------

def test_text_from_the_settings_and_the_address_is_shown_as_text(person, settings, monkeypatch):
    from maverick_dashboard import ekko_routes as ekko

    # A name that is not a known app never reaches the page at all...
    settings('[ekko]\nenable = true\nallowed_apps = ["excel", "<script>alert(1)</script>", "<b>word</b>"]\n')
    page = _page(person)
    assert "alert(1)" not in page and "<b>word</b>" not in page
    assert 'value="excel" checked> Microsoft Excel' in page
    # ...and a label is escaped wherever it is shown.
    monkeypatch.setitem(ekko._APP_NAMES, "excel", '<img src=x onerror="alert(2)">')
    page = _page(person)
    assert "<img src=x" not in page and "&lt;img src=x onerror=&#34;alert(2)&#34;&gt;" in page
    _enroll(person, apps=("excel",))
    page = _page(person)
    assert "<img src=x" not in page and "&lt;img src=x" in page

    # A device name that is not a name is refused, and never written into a page.
    for name in ('"><script>alert(3)</script>', "../desk", "desk name"):
        for accept in ("application/json", "text/html"):
            refused = person.get("/ekko", params={"device": name}, headers={"Accept": accept})
            assert refused.status_code == 422 and "alert(3)" not in refused.text and name not in refused.text


def test_the_page_needs_the_same_permission_as_its_calls(person, monkeypatch):
    from maverick_dashboard import auth

    def deny(request, permission, **_):
        from fastapi import HTTPException

        assert permission == "operate"
        raise HTTPException(status_code=403, detail="no")

    monkeypatch.setattr(auth, "require_permission", deny)
    assert person.get("/ekko").status_code == 403


def test_the_page_offers_no_view_across_people(person):
    whole = person.get("/ekko").text
    script = whole.split("<script nonce=", 1)[1]
    # Every call the page makes names one device of the signed-in person; none names a person.
    assert "owner" not in script and "principal" not in script and "user:" not in script
    for call in re.findall(r'"(/api/v1/[^"]*)"', script):
        assert call.startswith("/api/v1/ekko/"), call


def test_the_page_is_in_the_sidebar_only_for_people_who_may_record():
    from maverick_dashboard import ui_visibility

    def listed(role):
        return any(link["href"] == "/ekko" for group in ui_visibility.nav_groups(role) for link in group["links"])

    # The page's floor is the permission its calls check.
    assert all(listed(role) for role in ("admin", "governance_lead", "operator", None))
    assert not any(listed(role) for role in ("approver", "responder", "auditor", "viewer"))
