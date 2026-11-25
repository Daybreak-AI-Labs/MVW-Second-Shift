"""Hand-over from a person's own recorder: the device key and what it can do.

Hermetic. The recorder is a client that carries only its device key; the
person is a client of the same app. Where two people are needed they sign in
with real tokens, minted here and checked by the real verifier against a
stand-in key endpoint. Time is moved through the two documented seams:
``ekko_handover_api._now`` and the store ``ekko_routes._store`` builds.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

INSTRUCTIONS = "/api/v1/external/ekko/instructions"
HANDOVER = "/api/v1/external/ekko/handover"
ACCOUNT = "a" * 64
OTHER_ACCOUNT = "b" * 64
MARKER = "Payroll-2026-Alice-Secret.xlsx"
ISSUER = "https://login.example.test/contoso/v2.0"
AUDIENCE = "app-client-id"


def _settings_text(*, enable=True, apps=("excel", "powerpoint"), extra="") -> str:
    listed = ", ".join(f'"{app}"' for app in apps)
    return (f"[ekko]\nenable = {'true' if enable else 'false'}\nallowed_apps = [{listed}]\n"
            "min_occurrences = 2\nmin_distinct_days = 2\npoll_interval_seconds = 5\n" + extra)


@pytest.fixture
def settings(tmp_path, monkeypatch, request):
    """One installation with its own data folder and settings file; returns the writer."""
    from maverick import config, killswitch, world_model
    from maverick.audit import signing
    from maverick_dashboard import ekko_handover_api as handover

    # The posture CI asks for: under the production posture the activity
    # record is signed, with a key that is read once per process.
    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"ekko-handover-test:{request.node.nodeid}".encode()
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    signing._reset_injected_keypair_cache()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    for name in ("MAVERICK_EKKO", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER",
                 "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_OIDC_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")

    def write(text: str | None = None, **changes) -> None:
        (tmp_path / "config.toml").write_text(_settings_text(**changes) if text is None else text, encoding="utf-8")
        config.reset_config_cache()

    write()
    handover._rate_times.clear()
    handover._lease_renewed.clear()
    yield write
    killswitch.clear()
    signing._reset_injected_keypair_cache()
    config.reset_config_cache()


@pytest.fixture
def app(settings):
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def person(app):
    """The person's own browser: same origin, and (signed out, on this computer) the local owner."""
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _recorder(app, key: str) -> TestClient:
    """A recorder's view: a client that carries only its device key."""
    return TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {key}"})


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


def _switch(app_name: str, at: float | None = None, **more) -> dict:
    return {"app": app_name, "action": "switch", "object_type": "none", "duration_seconds": 0,
            "occurred_at": time.time() if at is None else at, **more}


def _batch(session_id: str, activities: list[dict], *, batch_id="batch-0001", account=ACCOUNT) -> dict:
    return {"session_id": session_id, "batch_id": batch_id, "account": account, "activities": activities}


def _count(person, device="desk") -> int:
    return person.get(f"/api/v1/ekko/status?device_id={device}").json()["event_count"]


def _stored(device="desk", owner: str | None = None):
    """What the store really holds for a device, read without any route."""
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    return WorkDiscoveryStore(owner or local_os_principal(), device).list_events()


@pytest.fixture
def recording(app, person):
    """An enrolled device with a key and a running session."""
    _enroll(person)
    key = _key(person)
    return SimpleNamespace(key=key, recorder=_recorder(app, key), session=_start(person), person=person)


# --- the whole path --------------------------------------------------------------

def test_from_consent_to_a_suggestion(app, person, monkeypatch):
    from maverick.paths import current_tenant_id
    from maverick.work_discovery_store import WorkDiscoveryStore
    from maverick_dashboard import ekko_handover_api as handover
    from maverick_dashboard import ekko_routes as ekko

    clock = SimpleNamespace(now=time.time() - 86_400)  # yesterday

    def moved_store(request, device_id):
        return WorkDiscoveryStore(ekko._owner(request), ekko._device_id(device_id),
                                  tenant=current_tenant_id(), clock=lambda: clock.now)

    monkeypatch.setattr(ekko, "_store", moved_store)
    monkeypatch.setattr(handover, "_now", lambda: clock.now)

    _enroll(person)
    recorder = _recorder(app, _key(person))
    waiting = recorder.get(INSTRUCTIONS).json()
    assert waiting["record"] is False and waiting["session"] == {"state": "none", "id": None}
    assert waiting["allowed_apps"] == ["excel", "powerpoint"] and waiting["poll_interval_seconds"] == 5

    def a_day_of_work(batch_id: str) -> str:
        session = _start(person)
        told = recorder.get(INSTRUCTIONS).json()
        assert told["record"] is True and told["session"] == {"state": "running", "id": session}
        clock.now += 60
        handed = recorder.post(HANDOVER, json=_batch(session, [
            _switch("excel", clock.now - 20), _switch("powerpoint", clock.now - 5)], batch_id=batch_id))
        assert handed.status_code == 200, handed.text
        assert handed.json() == {"accepted": 2, "dropped": 0, "duplicates": 0, "times_adjusted": 0}
        return session

    first = a_day_of_work("batch-day-1")
    assert _count(person) == 2
    early = person.post("/api/v1/ekko/candidates/mine", json={"device_id": "desk"}).json()
    assert early["count"] == 0 and "another day" in early["progress"]["next_step"]
    assert person.post(f"/api/v1/ekko/sessions/{first}/stop", json={"device_id": "desk"}).status_code == 200

    clock.now += 86_400  # the next day
    a_day_of_work("batch-day-2")
    assert _count(person) == 4
    found = person.post("/api/v1/ekko/candidates/mine", json={"device_id": "desk"}).json()
    assert found["count"] == 1
    (pattern,) = found["candidates"]
    assert pattern["title"] == "Recurring work across Microsoft Excel → Microsoft PowerPoint"
    assert pattern["occurrences"] == 2 and pattern["distinct_days"] == 2
    heard = person.get("/api/v1/ekko/device-key?device_id=desk").json()
    assert heard["has_key"] is True and heard["heard_recently"] is True


# --- who is refused -----------------------------------------------------------------

def test_no_key_and_keys_that_are_not_valid_are_refused(app, recording):
    from maverick import ekko_device_keys as keys

    public, secret = recording.key[len(keys.KEY_PREFIX):].split("_", 1)
    not_valid = [
        "ekr_" + "0" * 16 + "_" + "A" * 43,           # never issued
        f"ekr_{public}_" + "A" * 43,                  # a real key's public part with another secret
        recording.key[:-1],                           # cut short
        recording.key + "x",
        secret,
        "not-a-key",
    ]
    for path, call in ((INSTRUCTIONS, "get"), (HANDOVER, "post")):
        bare = getattr(TestClient(app, base_url="http://127.0.0.1"), call)(path)
        assert bare.status_code == 401 and bare.json()["detail"]["code"] == "missing_device_key"
        answers = [getattr(_recorder(app, key), call)(path) for key in not_valid]
        assert {answer.status_code for answer in answers} == {401}
        assert len({answer.text for answer in answers}) == 1  # nothing says which part was wrong
    basic = TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Basic {recording.key}"})
    assert basic.get(INSTRUCTIONS).status_code == 401
    assert _count(recording.person) == 0


def test_the_person_s_own_browser_is_not_a_recorder(recording):
    # Signed out on this computer the browser is the local owner everywhere
    # else; here it is nobody. (A signed-in session is tried further down.)
    assert recording.person.get("/api/v1/ekko/status?device_id=desk").status_code == 200
    assert recording.person.get(INSTRUCTIONS).status_code == 401
    refused = recording.person.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 401
    assert _count(recording.person) == 0


def _every_route(app):
    for path, operations in sorted(app.openapi()["paths"].items()):
        for method in sorted(operations):
            yield method.upper(), path


def test_a_device_key_opens_nothing_else(app, recording):
    recorder = recording.recorder
    # The same key sent from the product's own page address, as a browser would.
    from_the_page = TestClient(app, base_url="http://127.0.0.1", headers={
        "Origin": "http://127.0.0.1", "Authorization": f"Bearer {recording.key}"})
    stranger = _recorder(app, "ekr_" + "0" * 16 + "_" + "A" * 43)
    fills = {"{session_id}": recording.session, "{approval_id}": "1", "{goal_id}": "1"}
    tried = 0
    for method, path in _every_route(app):
        if path in (INSTRUCTIONS, HANDOVER):
            continue
        address = path
        for name, value in fills.items():
            address = address.replace(name, value)
        address = address.replace("{", "").replace("}", "")
        body = {} if method in {"POST", "PUT", "PATCH", "DELETE"} else None
        with_key = recorder.request(method, address, json=body, follow_redirects=False)
        # The key is worth exactly what a made-up one is worth: nothing.
        made_up = stranger.request(method, address, json=body, follow_redirects=False)
        assert with_key.status_code == made_up.status_code, (method, path)
        if path.startswith("/api/v1/") and not path.startswith("/api/v1/external/"):
            assert with_key.status_code in (401, 403), (method, path, with_key.status_code)
            assert from_the_page.request(method, address, json=body).status_code == 401, (method, path)
        tried += 1
    assert tried > 60
    for path in ("/ekko", "/ekko?device=desk", "/api/v1/ekko/device-key", "/api/v1/ekko/status?device_id=desk",
                 "/api/v1/ekko/candidates?device_id=desk", "/api/v1/ekko/sessions?device_id=desk",
                 "/api/v1/ekko/plans?device_id=desk"):
        assert recorder.get(path, follow_redirects=False).status_code == 401, path
    # Nothing was changed by any of those calls.
    status = recording.person.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["session"]["state"] == "running" and status["enrollment"]["active"] is True
    assert recorder.get(INSTRUCTIONS).json()["record"] is True


def test_another_device_s_key_cannot_hand_over_for_this_device(app, person, recording):
    _enroll(person, "laptop")
    laptop = _recorder(app, _key(person, "laptop"))
    assert laptop.get(INSTRUCTIONS).json()["session"] == {"state": "none", "id": None}
    refused = laptop.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "session_not_running"
    assert _count(person) == 0 and _count(person, "laptop") == 0
    # Each key still works for its own device.
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")])).json()["accepted"] == 1
    assert _count(person) == 1 and _count(person, "laptop") == 0


def test_a_paused_or_stopped_session_accepts_nothing(recording):
    person, recorder, session = recording.person, recording.recorder, recording.session

    def hand_over(batch_id):
        return recorder.post(HANDOVER, json=_batch(session, [_switch("excel")], batch_id=batch_id))

    assert hand_over("batch-0001").json()["accepted"] == 1
    assert person.post(f"/api/v1/ekko/sessions/{session}/pause", json={"device_id": "desk"}).status_code == 200
    told = recorder.get(INSTRUCTIONS).json()
    assert told["record"] is False and told["reason"] == "session_paused" and told["session"]["state"] == "paused"
    paused = hand_over("batch-0002")
    assert paused.status_code == 409 and paused.json()["detail"]["code"] == "session_not_running"
    assert _count(person) == 1

    assert person.post(f"/api/v1/ekko/sessions/{session}/resume", json={"device_id": "desk"}).status_code == 200
    assert recorder.get(INSTRUCTIONS).json()["record"] is True
    assert hand_over("batch-0003").json()["accepted"] == 1

    assert person.post(f"/api/v1/ekko/sessions/{session}/stop", json={"device_id": "desk"}).status_code == 200
    told = recorder.get(INSTRUCTIONS).json()
    assert told["record"] is False and told["session"] == {"state": "stopped", "id": None}
    assert hand_over("batch-0004").status_code == 409
    # A new session does not take what was noticed under the old one.
    newer = _start(person)
    assert hand_over("batch-0005").status_code == 409
    assert _count(person) == 2
    assert recorder.post(HANDOVER, json=_batch(newer, [_switch("excel")], batch_id="batch-0006")).json()["accepted"] == 1


def test_a_recorder_does_not_attach_to_a_session_that_is_not_running(recording):
    person, session = recording.person, recording.session
    assert person.post(f"/api/v1/ekko/sessions/{session}/pause", json={"device_id": "desk"}).status_code == 200
    assert recording.recorder.post(HANDOVER, json=_batch(session, [_switch("excel")])).status_code == 409
    assert person.get("/api/v1/ekko/status?device_id=desk").json()["collector_state"] == "waiting"


def test_the_recorder_cannot_start_a_session(app, person):
    _enroll(person)
    recorder = _recorder(app, _key(person))
    assert recorder.get(INSTRUCTIONS).json()["record"] is False
    for session in ("ekko-" + "0" * 24, "anything-else"):
        refused = recorder.post(HANDOVER, json=_batch(session, [_switch("excel")]))
        assert refused.status_code == 409 and refused.json()["detail"]["code"] == "session_not_running"
    from_the_page = TestClient(app, base_url="http://127.0.0.1", headers={**recorder.headers, "Origin": "http://127.0.0.1"})
    start = {"device_id": "desk", "acknowledge_capture_scope": True}
    assert from_the_page.post("/api/v1/ekko/sessions", json=start).status_code == 401
    assert recorder.post("/api/v1/ekko/sessions", json=start).status_code in (401, 403)
    status = person.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["session"] is None and status["event_count"] == 0


def _key_is_gone(recording):
    from maverick import ekko_device_keys as keys
    from maverick.work_discovery_identity import local_os_principal

    for answer in (recording.recorder.get(INSTRUCTIONS),
                   recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))):
        assert answer.status_code == 401 and answer.json()["detail"]["code"] == "invalid_device_key"
    assert keys.for_device(local_os_principal(), "desk", tenant=None) is None  # its record went with the consent
    assert recording.person.get("/api/v1/ekko/device-key?device_id=desk").json()["has_key"] is False


def test_withdrawing_consent_ends_the_key(recording):
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")])).json()["accepted"] == 1
    assert recording.person.post("/api/v1/ekko/revoke", json={"device_id": "desk"}).status_code == 200
    _key_is_gone(recording)
    assert _count(recording.person) == 1  # what was recorded stays until the person erases it


def test_forgetting_the_device_ends_the_key(recording):
    assert recording.person.delete("/api/v1/ekko/device?device_id=desk").status_code == 200
    _key_is_gone(recording)


def test_an_expired_enrollment_ends_the_key(recording, monkeypatch):
    from maverick_dashboard import ekko_handover_api as handover

    later = time.time() + 15 * 86_400  # the enrollment was for 14 days
    monkeypatch.setattr(handover, "_now", lambda: later)
    from maverick import ekko_device_keys as keys
    from maverick.work_discovery_identity import local_os_principal

    assert recording.recorder.get(INSTRUCTIONS).status_code == 401
    assert keys.for_device(local_os_principal(), "desk", tenant=None) is None  # removed at the first refusal
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel", later)])).status_code == 401
    assert _stored() == []


def test_enrolling_again_needs_a_new_key(app, recording):
    person = recording.person
    assert person.post(f"/api/v1/ekko/sessions/{recording.session}/stop", json={"device_id": "desk"}).status_code == 200
    _enroll(person, apps=("excel",))
    assert recording.recorder.get(INSTRUCTIONS).status_code == 401
    assert _recorder(app, _key(person)).get(INSTRUCTIONS).json()["allowed_apps"] == ["excel"]


def test_a_narrowed_app_list_stops_the_recorder_until_the_person_enrolls_again(recording, settings):
    settings(apps=("excel",))
    told = recording.recorder.get(INSTRUCTIONS).json()
    assert told["enrollment_current"] is False and told["record"] is False
    assert told["reason"] == "enrollment_not_current" and told["allowed_apps"] == []
    refused = recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "enrollment_not_current"
    assert _stored() == []


def test_ekko_turned_off_accepts_nothing(recording, settings):
    settings(enable=False)
    told = recording.recorder.get(INSTRUCTIONS).json()
    assert told["ekko_on"] is False and told["record"] is False and told["allowed_apps"] == []
    refused = recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "ekko_off"
    assert _stored() == []


def test_the_emergency_stop_accepts_nothing(recording, tmp_path):
    (tmp_path / "HALT").write_text("stop", encoding="utf-8")
    told = recording.recorder.get(INSTRUCTIONS).json()
    assert told["record"] is False and told["reason"] == "emergency_stop"
    refused = recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "emergency_stop"
    (tmp_path / "HALT").unlink()
    assert _stored() == []
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")])).json()["accepted"] == 1


def test_settings_that_cannot_be_read_accept_nothing(recording, settings):
    settings("[ekko\nenable = true")
    assert recording.recorder.get(INSTRUCTIONS).status_code == 503
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")])).status_code == 503
    settings()
    assert _stored() == []


def test_settings_that_cannot_be_read_accept_nothing_in_a_named_workspace(app, person, settings, monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "workspace-a")
    _enroll(person)
    recorder = _recorder(app, _key(person))
    session = _start(person)
    assert recorder.get(INSTRUCTIONS).json()["record"] is True
    settings("[ekko\nenable = true")
    assert recorder.get(INSTRUCTIONS).status_code == 503
    refused = recorder.post(HANDOVER, json=_batch(session, [_switch("excel")]))
    assert refused.status_code == 503 and refused.json()["detail"]["code"] == "settings_unreadable"
    settings()
    assert _count(person) == 0


def test_a_key_record_that_cannot_be_read_accepts_nothing(recording, tmp_path):
    with sqlite3.connect(tmp_path / "ekko" / "device-keys.sqlite3") as index:
        index.execute("UPDATE ekko_device_keys SET record = ?", (b"not the sealed record",))
    for answer in (recording.recorder.get(INSTRUCTIONS),
                   recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))):
        assert answer.status_code == 503 and answer.json()["detail"]["code"] == "not_accepted"
    assert _stored() == []
    # The person is told, and can always clear it.
    assert recording.person.get("/api/v1/ekko/device-key?device_id=desk").status_code == 503
    assert recording.person.delete("/api/v1/ekko/device-key?device_id=desk").json() == {"removed": True}
    assert recording.recorder.get(INSTRUCTIONS).status_code == 401


def test_a_key_record_given_another_hash_accepts_nothing(app, recording, tmp_path):
    from maverick import ekko_device_keys as keys

    # Someone who can write to the index, but cannot unseal a record, swaps in
    # the hash of a key they chose. The sealed record still names the real one.
    chosen = f"ekr_{recording.key[4:20]}_" + "B" * 43
    with sqlite3.connect(tmp_path / "ekko" / "device-keys.sqlite3") as index:
        index.execute("UPDATE ekko_device_keys SET key_hash = ?", (keys.hash_key(chosen),))
    forged = _recorder(app, chosen)
    assert forged.get(INSTRUCTIONS).status_code == 503
    assert forged.post(HANDOVER, json=_batch(recording.session, [_switch("excel")])).status_code == 503
    assert recording.recorder.get(INSTRUCTIONS).status_code == 401
    assert _stored() == []


def test_the_recorder_cannot_attach_when_the_audit_record_cannot_be_written(recording, monkeypatch):
    monkeypatch.setattr("maverick.audit.record", lambda *_a, **_k: False)
    refused = recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 503
    monkeypatch.undo()
    assert _stored() == []


# --- what is refused ------------------------------------------------------------------

def test_an_app_that_is_not_allowed_is_dropped_and_counted(recording):
    handed = recording.recorder.post(HANDOVER, json=_batch(recording.session, [
        _switch("excel"),
        _switch("word"),                                                   # a known app the administrator did not allow
        _switch("slack"),                                                  # always blocked
        {"app": "excel", "action": "download", "object_type": "report", "occurred_at": time.time()},  # more than a switch
        _switch("powerpoint"),
    ]))
    assert handed.status_code == 200
    assert handed.json() == {"accepted": 2, "dropped": 3, "duplicates": 0, "times_adjusted": 0}
    assert [(event.app, event.action, event.object_type) for event in _stored()] == [
        ("excel", "switch", "none"), ("powerpoint", "switch", "none")]


def test_an_app_the_person_did_not_choose_is_dropped(app, person):
    _enroll(person, apps=("excel",))
    recorder = _recorder(app, _key(person))
    handed = recorder.post(HANDOVER, json=_batch(_start(person), [_switch("excel"), _switch("powerpoint")]))
    assert handed.json()["accepted"] == 1 and handed.json()["dropped"] == 1
    assert [event.app for event in _stored()] == ["excel"]


def test_detailed_recording_does_not_widen_what_a_recorder_may_say(app, person, settings):
    settings(extra='capture_level = "guided"\n')
    _enroll(person)
    recorder = _recorder(app, _key(person))
    handed = recorder.post(HANDOVER, json=_batch(_start(person), [
        {"app": "excel", "action": "download", "object_type": "report", "occurred_at": time.time()},
        _switch("excel")]))
    assert handed.json()["accepted"] == 1 and handed.json()["dropped"] == 1
    assert [(event.action, event.object_type) for event in _stored()] == [("switch", "none")]


def _refused_bodies(session: str) -> dict[str, object]:
    good = _switch("excel")
    return {
        "an unknown field beside the activities": {**_batch(session, [good]), "note": MARKER},
        "an unknown field in an activity": _batch(session, [{**good, "window_title": MARKER}]),
        "a web address field": _batch(session, [{**good, "url": "https://example.test/" + MARKER}]),
        "an app name that is not in the list": _batch(session, [{**good, "app": MARKER}]),
        "an action that is not in the list": _batch(session, [{**good, "action": MARKER}]),
        "an object that is not in the list": _batch(session, [{**good, "object_type": MARKER}]),
        "an app that is not text": _batch(session, [{**good, "app": [MARKER]}]),
        "a time that is not a number": _batch(session, [{**good, "occurred_at": MARKER}]),
        "a time that is true": _batch(session, [{**good, "occurred_at": True}]),
        "a duration that is too long": _batch(session, [{**good, "duration_seconds": 1e9}]),
        "an activity without a time": _batch(session, [{"app": "excel", "action": "switch"}]),
        "an activity that is text": _batch(session, [MARKER]),
        "no activities": _batch(session, []),
        "activities that are not a list": _batch(session, {"app": MARKER}),
        "a batch id with spaces": _batch(session, [good], batch_id=MARKER + " 1"),
        "a short batch id": _batch(session, [good], batch_id="b1"),
        "an account that is a name": _batch(session, [good], account="CORP\\alice"),
        "a session id that is not an id": _batch("../" + MARKER, [good]),
        "no account": {k: v for k, v in _batch(session, [good]).items() if k != "account"},
        "a list": [MARKER],
        "text": MARKER,
    }


def test_an_unknown_field_or_value_refuses_the_whole_batch(recording):
    bodies = _refused_bodies(recording.session)
    raw = {"not json": b"{" + MARKER.encode(), "not text": b"\xff\xfe" + MARKER.encode(),
           "a number that is not one": json.dumps(_batch(recording.session, [_switch("excel")])).replace(
               '"duration_seconds": 0', '"duration_seconds": NaN').encode(),
           "nothing": b""}
    for name, body in {**bodies, **raw}.items():
        sent = {"content": body} if isinstance(body, bytes) else {"json": body}
        refused = recording.recorder.post(HANDOVER, **sent)
        assert refused.status_code == 422, name
        assert refused.json()["detail"]["code"] == "not_understood", name
        assert MARKER not in refused.text and "alice" not in refused.text, name
    assert _stored() == []
    # One bad activity refuses the good ones sent with it.
    mixed = _batch(recording.session, [_switch("excel"), {**_switch("excel"), "file_name": MARKER}])
    assert recording.recorder.post(HANDOVER, json=mixed).status_code == 422
    assert _stored() == []


def test_a_batch_that_is_too_large_is_refused(recording):
    from maverick_dashboard import ekko_handover_api as handover

    too_many = _batch(recording.session, [_switch("excel")] * (handover.MAX_BATCH_ACTIVITIES + 1))
    refused = recording.recorder.post(HANDOVER, json=too_many)
    assert refused.status_code == 413 and refused.json()["detail"]["code"] == "too_large"
    padded = json.dumps(_batch(recording.session, [_switch("excel")])).encode() + b" " * handover.MAX_BODY_BYTES
    assert recording.recorder.post(HANDOVER, content=padded).status_code == 413
    huge = recording.recorder.post(HANDOVER, content=b" " * (300 * 1024))
    assert huge.status_code == 413
    assert _stored() == []
    at_the_limit = _batch(recording.session, [_switch("excel"), _switch("powerpoint")] * (handover.MAX_BATCH_ACTIVITIES // 2))
    assert recording.recorder.post(HANDOVER, json=at_the_limit).json()["accepted"] == handover.MAX_BATCH_ACTIVITIES
    # Without a key the size is never looked at.
    assert TestClient(recording.person.app, base_url="http://127.0.0.1").post(HANDOVER, content=padded).status_code == 401


def test_a_batch_sent_again_is_stored_once(recording):
    batch = _batch(recording.session, [_switch("excel"), _switch("powerpoint"), _switch("slack")])
    first = recording.recorder.post(HANDOVER, json=batch)
    assert first.json() == {"accepted": 2, "dropped": 1, "duplicates": 0, "times_adjusted": 0}
    for _ in range(3):
        again = recording.recorder.post(HANDOVER, json=batch)
        assert again.status_code == 200
        assert again.json() == {"accepted": 0, "dropped": 1, "duplicates": 2, "times_adjusted": 0}
    assert [event.sequence for event in _stored()] == [1, 2]
    # The same batch with later times (a retry rebuilt after a wait) is still the same batch.
    later = _batch(recording.session, [_switch("excel", time.time() + 1), _switch("powerpoint", time.time() + 2),
                                       _switch("slack")])
    assert recording.recorder.post(HANDOVER, json=later).json()["accepted"] == 0
    # A new batch id is new work.
    assert recording.recorder.post(HANDOVER, json={**batch, "batch_id": "batch-0002"}).json()["accepted"] == 2
    assert [event.sequence for event in _stored()] == [1, 2, 3, 4]


def test_a_batch_half_stored_is_finished_by_its_retry(recording, monkeypatch):
    from maverick.work_discovery_store import WorkDiscoveryStore, WorkDiscoveryStoreError

    real = WorkDiscoveryStore.append_collector_event
    calls = []

    def fail_on_the_second(self, event, **kwargs):
        calls.append(event.app)
        if len(calls) == 2:
            raise WorkDiscoveryStoreError("storage is busy")
        return real(self, event, **kwargs)

    monkeypatch.setattr(WorkDiscoveryStore, "append_collector_event", fail_on_the_second)
    batch = _batch(recording.session, [_switch("excel"), _switch("powerpoint"), _switch("excel")])
    broken = recording.recorder.post(HANDOVER, json=batch)
    assert broken.status_code == 503 and "busy" not in broken.text
    assert [event.app for event in _stored()] == ["excel"]
    retried = recording.recorder.post(HANDOVER, json=batch)
    assert retried.json() == {"accepted": 2, "dropped": 0, "duplicates": 1, "times_adjusted": 0}
    assert [(event.sequence, event.app) for event in _stored()] == [(1, "excel"), (2, "powerpoint"), (3, "excel")]


def test_a_full_recording_takes_no_more(recording, monkeypatch):
    from maverick_dashboard import ekko_handover_api as handover

    monkeypatch.setattr(handover, "MAX_EVENTS_PER_SESSION", 2)
    full = recording.recorder.post(HANDOVER, json=_batch(recording.session, [
        _switch("excel"), _switch("powerpoint"), _switch("excel")]))
    assert full.status_code == 409 and full.json()["detail"]["code"] == "session_full"
    assert [event.app for event in _stored()] == ["excel", "powerpoint"]


def test_the_time_rule():
    from maverick_dashboard.ekko_handover_api import MAX_ACTIVITY_AGE_SECONDS, kept_time

    now, started = 1_800_000_000.0, 1_800_000_000.0 - 3_600
    assert MAX_ACTIVITY_AGE_SECONDS == 600

    def kept(sent, previous=None, session_started=started):
        return kept_time(sent, now=now, session_started=session_started, previous=previous)

    assert kept(now - 30) == now - 30                 # believable: kept as sent
    assert kept(now + 1) == now                       # not in the future
    assert kept(now + 86_400) == now
    assert kept(now - 600) == now - 600               # the edge of the window
    assert kept(now - 601) == now - 600               # not older than ten minutes
    assert kept(now - 3 * 86_400) == now - 600        # never another day
    assert kept(now - 300, session_started=now - 60) == now - 60   # not before the person pressed Start
    assert kept(now - 300, previous=now - 100) == now - 100        # not before the one kept just before it
    assert kept(now - 50, previous=now - 100) == now - 50
    assert kept(now + 5, previous=now + 1) == now + 1               # order wins, even over "not in the future"


def test_times_in_the_future_or_too_old_are_not_kept_as_sent(recording, monkeypatch):
    from maverick_dashboard import ekko_handover_api as handover

    now = time.time() + 3_600  # an hour into the session
    monkeypatch.setattr(handover, "_now", lambda: now)
    handed = recording.recorder.post(HANDOVER, json=_batch(recording.session, [
        _switch("excel", now - 3 * 86_400),      # three days ago
        _switch("powerpoint", now - 30),         # believable
        _switch("excel", now + 86_400),          # tomorrow
        _switch("powerpoint", now - 200),        # earlier than the one before it
    ]))
    assert handed.json() == {"accepted": 4, "dropped": 0, "duplicates": 0, "times_adjusted": 3}
    assert [event.occurred_at for event in _stored()] == [now - 600, now - 30, now, now]
    assert len({event.day for event in _stored()}) <= 2  # ten minutes can cross midnight, never more


def test_a_different_computer_account_is_refused_and_recorded_once(app, recording, monkeypatch):
    from maverick_dashboard import ekko_routes as ekko

    recorder, session = recording.recorder, recording.session
    assert recorder.post(HANDOVER, json=_batch(session, [_switch("excel")])).json()["accepted"] == 1
    written = []
    real = ekko._audit
    monkeypatch.setattr(ekko, "_audit", lambda kind, **payload: written.append((str(kind), payload)) or real(kind, **payload))
    for batch_id in ("batch-0002", "batch-0003", "batch-0004"):
        refused = recorder.post(HANDOVER, json=_batch(session, [_switch("powerpoint")], batch_id=batch_id, account=OTHER_ACCOUNT))
        assert refused.status_code == 403 and refused.json()["detail"]["code"] == "different_account"
        assert OTHER_ACCOUNT not in refused.text and ACCOUNT not in refused.text
    assert written == [("ekko_session", {"state": "handover_refused", "reason": "different_computer_account"})]
    assert [event.app for event in _stored()] == ["excel"]
    # Nor does the other account become the recorder of a new session.
    person = recording.person
    assert person.post(f"/api/v1/ekko/sessions/{session}/stop", json={"device_id": "desk"}).status_code == 200
    session = _start(person)
    written.clear()
    assert recorder.post(HANDOVER, json=_batch(session, [_switch("excel")], account=OTHER_ACCOUNT)).status_code == 403
    assert not [payload for _, payload in written if payload.get("observer") == "device_recorder"]
    assert person.get("/api/v1/ekko/status?device_id=desk").json()["collector_state"] == "waiting"
    # The first account is still accepted, and a new key starts again.
    assert recorder.post(HANDOVER, json=_batch(session, [_switch("powerpoint")], batch_id="batch-0005")).json()["accepted"] == 1
    replaced = _recorder(app, _key(recording.person))
    moved = replaced.post(HANDOVER, json=_batch(session, [_switch("excel")], batch_id="batch-0006", account=OTHER_ACCOUNT))
    assert moved.json()["accepted"] == 1
    assert replaced.post(HANDOVER, json=_batch(session, [_switch("excel")], batch_id="batch-0007")).status_code == 403


def test_a_recorder_that_keeps_asking_stays_attached(recording, monkeypatch):
    from maverick_dashboard import ekko_handover_api as handover
    from maverick_dashboard import ekko_routes as ekko

    clock = SimpleNamespace(now=time.time())
    monkeypatch.setattr(handover, "_now", lambda: clock.now)
    attached = []
    real = ekko._audit
    monkeypatch.setattr(ekko, "_audit", lambda kind, **payload: (
        attached.append(payload["state"]) if payload.get("observer") == "device_recorder" else None) or real(kind, **payload))

    def hand_over(batch_id):
        handed = recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel", clock.now)], batch_id=batch_id))
        assert handed.json()["accepted"] == 1, handed.text

    hand_over("batch-0001")
    for _ in range(8):  # quiet minutes: nothing to hand over, but the recorder keeps asking
        clock.now += 25
        assert recording.recorder.get(INSTRUCTIONS).json()["record"] is True
    hand_over("batch-0002")
    assert attached == ["start_authorized"]  # attached once
    assert recording.person.get("/api/v1/ekko/status?device_id=desk").json()["collector_state"] == "live"

    clock.now += 300  # the recorder was away longer than its lease
    hand_over("batch-0003")
    assert attached == ["start_authorized", "start_authorized"]  # coming back is attaching again, and is recorded


def test_a_second_recorder_cannot_join_while_another_holds_the_device(recording):
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    store = WorkDiscoveryStore(local_os_principal(), "desk")
    store.claim_collector(recording.session, "collector-on-the-server", policy=store.get_policy(), ttl_seconds=30)
    refused = recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")]))
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "another_recorder"
    assert _stored() == []


# --- the key ----------------------------------------------------------------------------

def test_replacing_or_removing_the_key_ends_the_old_one(app, person, monkeypatch):
    from maverick_dashboard import ekko_routes as ekko

    states = []
    real = ekko._audit
    monkeypatch.setattr(ekko, "_audit", lambda kind, **payload: states.append((str(kind), payload)) or real(kind, **payload))
    _enroll(person)
    states.clear()
    first = _key(person)
    assert states == [("ekko_consent_changed", {"required": True, "state": "device_key_authorized"}),
                      ("ekko_consent_changed", {"state": "device_key_created"})]
    session = _start(person)
    assert _recorder(app, first).post(HANDOVER, json=_batch(session, [_switch("excel")])).json()["accepted"] == 1

    second = _key(person)
    assert second != first
    assert _recorder(app, first).get(INSTRUCTIONS).status_code == 401
    assert _recorder(app, first).post(HANDOVER, json=_batch(session, [_switch("excel")], batch_id="batch-0002")).status_code == 401
    assert _recorder(app, second).get(INSTRUCTIONS).json()["record"] is True

    states.clear()
    assert person.delete("/api/v1/ekko/device-key?device_id=desk").json() == {"removed": True}
    assert states == [("ekko_consent_changed", {"state": "device_key_revoked"})]
    assert _recorder(app, second).get(INSTRUCTIONS).status_code == 401
    assert person.delete("/api/v1/ekko/device-key?device_id=desk").json() == {"removed": False}
    assert person.get("/api/v1/ekko/device-key?device_id=desk").json() == {
        "device_id": "desk", "has_key": False, "created_at": None, "last_heard_at": None, "heard_recently": False}
    assert _count(person) == 1  # removing a key erases nothing


def test_the_key_is_shown_once_and_only_its_hash_is_kept(person, tmp_path):
    from maverick import ekko_device_keys as keys

    _enroll(person, "desk-computer-7")
    created = person.post("/api/v1/ekko/device-key", json={"device_id": "desk-computer-7"})
    assert created.headers["cache-control"] == "no-store"
    body = created.json()
    key = body.pop("device_key")
    assert keys._KEY_RE.fullmatch(key) and key not in json.dumps(body) and keys.hash_key(key) not in created.text
    seen_again = person.get("/api/v1/ekko/device-key?device_id=desk-computer-7")
    assert key not in seen_again.text and key[21:] not in seen_again.text and keys.hash_key(key) not in seen_again.text
    on_disk = b"".join(path.read_bytes() for path in (tmp_path / "ekko").rglob("*") if path.is_file())
    assert key.encode() not in on_disk and key[21:].encode() not in on_disk
    assert keys.hash_key(key).encode() in on_disk
    # Who is recorded, and on which computer, is sealed: the index names nobody.
    assert b"desk-computer-7" not in on_disk and b"os:posix" not in on_disk and b"os:windows" not in on_disk


def test_creating_a_key_needs_consent_the_page_and_permission(app, person, settings, monkeypatch):
    from maverick import ekko_device_keys as keys
    from maverick.work_discovery_identity import local_os_principal
    from maverick_dashboard import auth

    def no_key():
        return keys.for_device(local_os_principal(), "desk", tenant=None) is None

    not_enrolled = person.post("/api/v1/ekko/device-key", json={"device_id": "desk"})
    assert not_enrolled.status_code == 409 and "not enrolled" in not_enrolled.json()["detail"]
    _enroll(person)
    elsewhere = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://elsewhere.example"})
    assert elsewhere.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 403
    assert elsewhere.delete("/api/v1/ekko/device-key?device_id=desk").status_code == 403
    injected = person.post("/api/v1/ekko/device-key", json={"device_id": "desk", "owner": "user:mallory"})
    assert injected.status_code == 422
    assert person.post("/api/v1/ekko/device-key", json={"device_id": "../desk"}).status_code == 422

    settings(enable=False)
    off = person.post("/api/v1/ekko/device-key", json={"device_id": "desk"})
    assert off.status_code == 409 and "turned off" in off.json()["detail"]
    settings(apps=("excel",))
    narrowed = person.post("/api/v1/ekko/device-key", json={"device_id": "desk"})
    assert narrowed.status_code == 409 and "Enroll this device again" in narrowed.json()["detail"]
    settings()

    with monkeypatch.context() as patch:
        patch.setattr("maverick.audit.record", lambda *_a, **_k: False)
        assert person.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 503
    assert no_key()

    def deny(request, permission, **_):
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="no")

    with monkeypatch.context() as patch:
        patch.setattr(auth, "require_permission", deny)
        assert person.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 403
        assert person.get("/api/v1/ekko/device-key?device_id=desk").status_code == 403
        assert person.delete("/api/v1/ekko/device-key?device_id=desk").status_code == 403
    assert no_key()
    assert person.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 201


# --- what is said, logged and recorded -----------------------------------------------------

def test_no_key_hash_or_activity_text_is_repeated_anywhere(app, person, monkeypatch, caplog):
    from maverick import audit
    from maverick import ekko_device_keys as keys

    caplog.set_level(logging.DEBUG)
    rows = []
    real = audit.record
    monkeypatch.setattr(audit, "record", lambda kind, **payload: rows.append((kind, payload)) or real(kind, **payload))

    _enroll(person)
    key = _key(person)
    recorder = _recorder(app, key)
    session = _start(person)
    good = _switch("excel")
    answers = [
        recorder.get(INSTRUCTIONS),
        recorder.post(HANDOVER, json=_batch(session, [good, _switch("powerpoint"), _switch("word")])),
        recorder.post(HANDOVER, json=_batch(session, [good, _switch("powerpoint"), _switch("word")])),         # a replay
        recorder.post(HANDOVER, json=_batch(session, [{**good, "window_title": MARKER}])),                     # an unknown field
        recorder.post(HANDOVER, json=_batch(session, [{**good, "app": MARKER}])),                              # text as an app
        recorder.post(HANDOVER, json=_batch(session, [good], batch_id="batch-0002", account=OTHER_ACCOUNT)),   # another account
        recorder.post(HANDOVER, json=_batch("ekko-" + "0" * 24, [good])),                                      # not its session
        recorder.post(HANDOVER, content=b"x" * 20_000),                                                        # too large
        _recorder(app, key[:-1] + ("A" if key[-1] != "A" else "B")).post(HANDOVER, json=_batch(session, [good])),
        person.get("/api/v1/ekko/device-key?device_id=desk"),
        person.get("/ekko?device=desk"),
    ]
    assert [answer.status_code for answer in answers] == [200, 200, 200, 422, 422, 403, 409, 413, 401, 200, 200]
    said = "\n".join(answer.text for answer in answers)
    logged = "\n".join(record.getMessage() for record in caplog.records)
    recorded = json.dumps(rows, default=str)
    for secret in (key, key[21:], keys.hash_key(key), keys.hash_key(key)[7:], MARKER, ACCOUNT, OTHER_ACCOUNT):
        assert secret not in said and secret not in logged and secret not in recorded
    # What was noticed is counted, never named: not in a hand-over's reply, the log or the audit record.
    for answer in answers[1:9]:
        assert "excel" not in answer.text and "powerpoint" not in answer.text and "word" not in answer.text
    for name in ("excel", "powerpoint"):
        assert name not in logged.lower() and name not in recorded.lower()
    kinds = {(kind, payload.get("state")) for kind, payload in rows}
    assert {("ekko_consent_changed", "device_key_authorized"), ("ekko_consent_changed", "device_key_created"),
            ("ekko_session", "start_authorized"), ("ekko_session", "handover_refused")} <= kinds
    attached = [payload for kind, payload in rows if payload.get("observer") == "device_recorder"]
    assert len(attached) == 1  # the replay and the later batches did not attach again
    assert set(attached[0]) == {"agent", "goal_id", "session_id", "state", "policy_digest", "observer"}


# --- limits ---------------------------------------------------------------------------------

def test_a_device_may_only_call_so_often(app, person, recording, monkeypatch):
    from maverick_dashboard import ekko_handover_api as handover

    monkeypatch.setattr(handover, "_RATE_LIMITS", {"instructions": 3, "handover": 2, "refused": 2})
    handover._rate_times.clear()
    recorder = recording.recorder
    assert [recorder.get(INSTRUCTIONS).status_code for _ in range(5)] == [200, 200, 200, 429, 429]
    limited = recorder.get(INSTRUCTIONS)
    assert limited.headers["retry-after"] == "60" and limited.json()["detail"]["code"] == "slow_down"
    handed = [recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")], batch_id=f"batch-000{n}"))
              for n in range(4)]
    assert [answer.status_code for answer in handed] == [200, 200, 429, 429]
    assert _count(person) == 2
    # Another device has its own allowance.
    _enroll(person, "laptop")
    assert _recorder(app, _key(person, "laptop")).get(INSTRUCTIONS).status_code == 200
    # Keys that are not valid are turned away before they are looked up.
    wrong = _recorder(app, "ekr_" + "0" * 16 + "_" + "A" * 43)
    assert [wrong.get(INSTRUCTIONS).status_code for _ in range(4)] == [401, 401, 429, 429]


# --- one person, one workspace -----------------------------------------------------------------

def test_a_key_stays_in_the_workspace_it_was_created_in(app, person, recording, monkeypatch):
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")])).json()["accepted"] == 1
    monkeypatch.setenv("MAVERICK_TENANT", "another-workspace")
    assert recording.recorder.get(INSTRUCTIONS).status_code == 401
    assert recording.recorder.post(HANDOVER, json=_batch(recording.session, [_switch("excel")], batch_id="batch-0002")).status_code == 401
    there = person.get("/api/v1/ekko/status?device_id=desk").json()
    assert there["enrollment"] is None and there["session"] is None and there["event_count"] == 0
    assert person.get("/api/v1/ekko/device-key?device_id=desk").json()["has_key"] is False
    assert person.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 409
    monkeypatch.delenv("MAVERICK_TENANT")
    assert recording.recorder.get(INSTRUCTIONS).status_code == 200
    assert _count(person) == 1


# Two people: real sign-in tokens, checked by the real verifier.
jwt = pytest.importorskip("jwt", reason="sign-in needs PyJWT")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def signed_in(settings, monkeypatch, signing_key):
    """Sign-in is on; returns a function giving a signed-in person's client."""
    from maverick import _oidc_jwks
    from maverick_dashboard import oidc_login
    from maverick_dashboard.app import app

    for name, value in {
        "MAVERICK_OIDC_ENABLED": "1", "MAVERICK_OIDC_ISSUER": ISSUER, "MAVERICK_OIDC_AUDIENCE": AUDIENCE,
        "MAVERICK_OIDC_JWKS_URI": "https://login.example.test/contoso/keys",
        "MAVERICK_OIDC_CLIENT_ID": AUDIENCE, "MAVERICK_OIDC_CLIENT_SECRET": "test-client-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_REDIRECT_URI": "http://127.0.0.1/auth/callback",
        "MAVERICK_OIDC_SESSION_SECRET": "unit-test-session-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT": "https://login.example.test/contoso/authorize",
        "MAVERICK_OIDC_TOKEN_ENDPOINT": "https://login.example.test/contoso/token",
    }.items():
        monkeypatch.setenv(name, value)

    class KeyEndpoint:
        def __init__(self, uri, **kwargs):
            pass

        def get_signing_keys(self, *, refresh):
            return [SimpleNamespace(key_id="k1", key=signing_key.public_key())]

    monkeypatch.setattr(jwt, "PyJWKClient", KeyEndpoint)
    _oidc_jwks._resolvers.clear()
    oidc_login._CONSUMED_TX_IDS.clear()
    settings(extra='\n[auth.oidc.role_map]\n"SecondShift.Operator" = "operator"\n')

    def token(sub: str, **claims) -> str:
        now = int(time.time())
        body = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 600,
                "roles": ["SecondShift.Operator"], **claims}
        return jwt.encode(body, signing_key, algorithm="RS256", headers={"kid": "k1"})

    def client(sub: str) -> TestClient:
        return TestClient(app, base_url="http://127.0.0.1", headers={
            "Origin": "http://127.0.0.1", "Authorization": "Bearer " + token(sub)})

    client.token, client.app = token, app
    yield client
    _oidc_jwks._resolvers.clear()
    oidc_login._CONSUMED_TX_IDS.clear()


def test_one_person_s_key_and_recordings_are_not_another_s(signed_in):
    alice, bob = signed_in("alice"), signed_in("bob")
    _enroll(alice)
    alice_key = _key(alice)
    alice_session = _start(alice)
    alice_recorder = _recorder(signed_in.app, alice_key)
    assert alice_recorder.post(HANDOVER, json=_batch(alice_session, [_switch("excel")])).json()["accepted"] == 1
    assert _count(alice) == 1

    # Bob names the same device and sees nothing of Alice's.
    assert bob.get("/api/v1/ekko/device-key?device_id=desk").json()["has_key"] is False
    status = bob.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["enrollment"] is None and status["session"] is None and status["event_count"] == 0
    assert bob.get("/api/v1/ekko/sessions?device_id=desk").json()["sessions"] == []
    assert bob.post("/api/v1/ekko/candidates/mine", json={"device_id": "desk"}).json()["progress"]["activities"] == 0
    page = bob.get("/ekko?device=desk").text
    assert alice_session not in page and "You have not given consent" in page
    # A page somewhere else cannot create or remove a key with her sign-in.
    elsewhere = TestClient(signed_in.app, base_url="http://127.0.0.1", headers={
        "Origin": "http://elsewhere.example", "Authorization": alice.headers["Authorization"]})
    assert elsewhere.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 403
    assert elsewhere.delete("/api/v1/ekko/device-key?device_id=desk").status_code == 403
    assert alice_recorder.get(INSTRUCTIONS).json()["record"] is True
    # He cannot create, replace or remove her key, or stop her session.
    assert bob.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).status_code == 409
    assert bob.delete("/api/v1/ekko/device-key?device_id=desk").json() == {"removed": False}
    assert bob.post(f"/api/v1/ekko/sessions/{alice_session}/stop", json={"device_id": "desk"}).status_code == 404
    assert alice_recorder.get(INSTRUCTIONS).json()["record"] is True

    # His own device of the same name is his own.
    _enroll(bob)
    bob_recorder = _recorder(signed_in.app, _key(bob))
    assert alice_recorder.get(INSTRUCTIONS).json()["record"] is True  # her key was not replaced by his
    bob_session = _start(bob)
    crossed = bob_recorder.post(HANDOVER, json=_batch(alice_session, [_switch("powerpoint")]))
    assert crossed.status_code == 409
    assert bob_recorder.post(HANDOVER, json=_batch(bob_session, [_switch("powerpoint")], account=OTHER_ACCOUNT)).json()["accepted"] == 1
    assert [event.app for event in _stored(owner="user:alice")] == ["excel"]
    assert [event.app for event in _stored(owner="user:bob")] == ["powerpoint"]
    assert _count(alice) == 1 and _count(bob) == 1


def test_a_signed_in_browser_session_is_not_a_recorder(signed_in, monkeypatch):
    from urllib.parse import parse_qs, urlparse

    from maverick_dashboard import oidc_login

    alice = signed_in("alice")
    _enroll(alice)
    key = _key(alice)
    session = _start(alice)

    browser = TestClient(signed_in.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    location = browser.get("/auth/login", follow_redirects=False).headers["location"]
    query = parse_qs(urlparse(location).query)
    id_token = signed_in.token("alice", nonce=query["nonce"][0])

    async def exchange(url, *, cfg, code, code_verifier):
        return {"id_token": id_token}

    monkeypatch.setattr(oidc_login, "_exchange_code_for_tokens", exchange)
    assert browser.get(f"/auth/callback?code=c&state={query['state'][0]}", follow_redirects=False).status_code == 303
    assert browser.get("/api/v1/ekko/status?device_id=desk").json()["session"]["state"] == "running"  # she is signed in

    assert browser.get(INSTRUCTIONS).status_code == 401
    assert browser.post(HANDOVER, json=_batch(session, [_switch("excel")])).status_code == 401
    # Her sign-in token is not a device key either, and the device key is not a sign-in.
    assert alice.get(INSTRUCTIONS).status_code == 401
    assert alice.post(HANDOVER, json=_batch(session, [_switch("excel")])).status_code == 401
    assert _recorder(signed_in.app, key).get("/api/v1/ekko/status?device_id=desk").status_code == 401
    assert _count(alice) == 0
    # A browser that is signed in and also sends the key is the recorder, and no more than that.
    browser.headers["Authorization"] = f"Bearer {key}"
    assert browser.get(INSTRUCTIONS).json()["record"] is True


def test_with_a_workspace_for_each_person_a_key_writes_only_into_its_person_s(signed_in, monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    alice, bob = signed_in("alice"), signed_in("bob")
    _enroll(alice)
    recorder = _recorder(signed_in.app, _key(alice))
    session = _start(alice)
    assert recorder.get(INSTRUCTIONS).json()["record"] is True
    assert recorder.post(HANDOVER, json=_batch(session, [_switch("excel")])).json()["accepted"] == 1
    assert _count(alice) == 1 and _count(bob) == 0
    # If workspaces are rearranged, the key is refused instead of writing where she cannot see it.
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER")
    assert recorder.get(INSTRUCTIONS).status_code == 401
    assert recorder.post(HANDOVER, json=_batch(session, [_switch("excel")], batch_id="batch-0002")).status_code == 401
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    assert _count(alice) == 1


def test_postgres_handover_rejects_wrong_account_and_replays_once(app, person, records_in_postgres):
    from maverick import ekko_device_keys
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    _enroll(person)
    key = _key(person)
    session = _start(person)
    recorder = _recorder(app, key)
    assert recorder.get(INSTRUCTIONS).status_code == 200
    batch = _batch(session, [_switch("excel")])
    assert recorder.post(HANDOVER, json=batch).status_code == 200
    assert recorder.post(HANDOVER, json=batch).status_code == 200
    wrong = {**_batch(session, [_switch("excel")], batch_id="batch-0002"), "account": OTHER_ACCOUNT}
    assert recorder.post(HANDOVER, json=wrong).status_code == 403
    assert _count(person) == 1
    assert not ekko_device_keys._path().exists()
    assert not WorkDiscoveryStore(local_os_principal(), "desk").path.exists()
