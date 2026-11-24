"""Ekko dashboard lifecycle, discovery, and preview-only authoring handoff."""
from __future__ import annotations

import sqlite3
from datetime import datetime, time, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from maverick import config
from maverick.work_discovery_planning import BenefitAssumptions, OpportunityPlans, pilot_summary
from maverick.work_discovery_store import WorkDiscoveryStore
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(tmp_path, monkeypatch, *, enabled: bool = True):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "\n".join([
            "[ekko]",
            f"enable = {'true' if enabled else 'false'}",
            'capture_level = "application_metadata"',
            'allowed_apps = ["excel", "powerpoint"]',
            (
                'blocked_apps = ["email", "outlook", "gmail", "chat", "teams", '
                '"slack", "crm", "salesforce", "erp", "sap", "database"]'
            ),
            "retention_days = 14",
            "min_occurrences = 2",
            "min_distinct_days = 2",
            "poll_interval_seconds = 5",
            "provider_egress = false",
            "",
        ]),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    for name in ("MAVERICK_EKKO", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    from maverick.config import reset_config_cache

    reset_config_cache()
    return cfg


def _enroll(owner: str | None = None, device: str = "desk"):
    from maverick.config import get_ekko_policy
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    store = WorkDiscoveryStore(owner or local_os_principal(), device)
    store.enroll(get_ekko_policy())
    return store


def _seed_recurring_evidence(store, *, guided=False) -> None:
    from maverick.work_discovery import SessionState, WorkEvent

    policy = store.get_policy()
    assert policy is not None
    first_day = datetime.now(timezone.utc).date() - timedelta(days=2)
    base = datetime.combine(first_day, time(hour=12), tzinfo=timezone.utc).timestamp()
    for day in range(2):
        session = store.create_session(
            policy=policy,
            session_id=f"repeat-{day}",
            started_at=base + day * 86_400,
        )
        collector_id = f"collector-seed-{day}"
        store.claim_collector(
            session.session_id,
            collector_id,
            policy=policy,
            ttl_seconds=30,
        )
        store.append_event(WorkEvent(
            event_id=f"event-{day}-1",
            session_id=session.session_id,
            sequence=1,
            occurred_at=base + day * 86_400 + 10,
            app="excel",
            action="download" if guided else "switch",
            object_type="report" if guided else "none",
            duration_seconds=120,
        ), policy=policy, collector_id=collector_id)
        store.append_event(WorkEvent(
            event_id=f"event-{day}-2",
            session_id=session.session_id,
            sequence=2,
            occurred_at=base + day * 86_400 + 140,
            app="powerpoint",
            action="create" if guided else "switch",
            object_type="presentation" if guided else "none",
            duration_seconds=480,
        ), policy=policy, collector_id=collector_id)
        store.transition_session(
            session.session_id,
            SessionState.STOPPED,
            at=base + day * 86_400 + 700,
        )


def test_status_is_default_off_and_payload_cannot_inject_owner_or_tenant(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch, enabled=False)
    status = client.get("/api/v1/ekko/status?device_id=desk")
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    assert status.json()["enrollment"] is None

    injected = client.post(
        "/api/v1/ekko/sessions",
        json={
            "device_id": "desk",
            "acknowledge_capture_scope": True,
            "owner": "user:mallory",
            "tenant": "other-client",
        },
    )
    assert injected.status_code == 422


def test_owner_bound_session_start_pause_resume_stop(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enroll(device="desk")

    missing_ack = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": False},
    )
    assert missing_ack.status_code == 400

    started = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": True},
    )
    assert started.status_code == 201
    session_id = started.json()["session"]["session_id"]
    assert started.json()["session"]["state"] == "running"
    assert started.json()["unsaved"] is True

    for action, expected in (
        ("pause", "paused"),
        ("resume", "running"),
        ("stop", "stopped"),
    ):
        response = client.post(
            f"/api/v1/ekko/sessions/{session_id}/{action}",
            json={"device_id": "desk"},
        )
        assert response.status_code == 200
        assert response.json()["session"]["state"] == expected

    # A different device selector remains inside the same owner but cannot see
    # or mutate the enrolled device's session.
    hidden = client.get("/api/v1/ekko/status?device_id=other-device").json()
    assert hidden["session"] is None and hidden["event_count"] == 0
    denied = client.post(
        f"/api/v1/ekko/sessions/{session_id}/pause",
        json={"device_id": "other-device"},
    )
    assert denied.status_code == 404


def test_forget_device_revokes_enrollment_and_erases_data(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = _enroll(device="desk")
    session = store.create_session(policy=store.get_policy())

    forgotten = client.delete("/api/v1/ekko/device?device_id=desk")

    assert forgotten.status_code == 200
    assert forgotten.json()["forgotten"]["enrollments"] == 1
    status = client.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["enrollment"] is None
    assert status["session"] is None
    assert store.get_session(session.session_id) is None


def test_enroll_from_the_page_narrows_apps_and_is_audited(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    status = client.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["app_choices"] == [
        {"value": "excel", "label": "Microsoft Excel"},
        {"value": "powerpoint", "label": "Microsoft PowerPoint"},
    ]
    assert status["enrollment_days"] == 30

    base = {"device_id": "desk", "apps": ["excel"], "days": 14}
    assert client.post("/api/v1/ekko/enroll", json=base).status_code == 400  # no consent tick
    outside = client.post("/api/v1/ekko/enroll", json={**base, "apps": ["slack"], "acknowledge_capture_scope": True})
    assert outside.status_code == 422
    assert "apps your administrator allows" in outside.json()["detail"]
    assert client.post("/api/v1/ekko/enroll", json={**base, "days": 365, "acknowledge_capture_scope": True}).status_code == 422
    injected = client.post("/api/v1/ekko/enroll", json={**base, "acknowledge_capture_scope": True, "owner": "user:mallory"})
    assert injected.status_code == 422

    kinds: list[tuple[str, dict]] = []
    from maverick_dashboard import ekko_routes

    real = ekko_routes._audit

    def spy(kind, **payload):
        kinds.append((str(kind), payload))
        return real(kind, **payload)

    monkeypatch.setattr(ekko_routes, "_audit", spy)
    enrolled = client.post("/api/v1/ekko/enroll", json={**base, "acknowledge_capture_scope": True})
    assert enrolled.status_code == 200, enrolled.text
    body = enrolled.json()
    assert body["status"]["enrollment"]["active"] is True
    assert body["status"]["allowed_apps"] == ["excel"]  # narrowed, never widened
    assert [p.get("state") for _, p in kinds] == ["enroll_authorized", "enrolled"]
    assert kinds[0][1]["required"] is True
    # enrolling only records consent; nothing is watched yet
    assert body["status"]["session"] is None

    started = client.post("/api/v1/ekko/sessions", json={"device_id": "desk", "acknowledge_capture_scope": True})
    assert started.status_code == 201
    revoked = client.post("/api/v1/ekko/revoke", json={"device_id": "desk"})
    assert revoked.status_code == 200 and revoked.json()["revoked"] is True
    after = revoked.json()["status"]
    assert not (after["enrollment"] or {}).get("active")
    assert after["session"]["state"] == "stopped"


def test_enroll_needs_ekko_on_and_operate(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch, enabled=False)
    off = client.post("/api/v1/ekko/enroll", json={"device_id": "desk", "apps": ["excel"],
                                                   "acknowledge_capture_scope": True})
    assert off.status_code == 409
    assert "turned off" in off.json()["detail"]
    from maverick_dashboard import auth

    def deny(request, permission):
        from fastapi import HTTPException
        assert permission == "operate"
        raise HTTPException(status_code=403, detail="no")

    monkeypatch.setattr(auth, "require_permission", deny)
    assert client.post("/api/v1/ekko/enroll", json={"device_id": "desk", "apps": ["excel"],
                                                    "acknowledge_capture_scope": True}).status_code == 403
    assert client.post("/api/v1/ekko/revoke", json={"device_id": "desk"}).status_code == 403


def _review_payload(candidate, kind="flow"):
    return {"device_id": "desk", "kind": kind, "evidence_revision": candidate["evidence_revision"], "review": {
        "goal": "Prepare a weekly summary", "inputs": "The export selected for this run",
        "output": "A presentation with totals and exceptions", "approval": "I verify figures before sharing",
    }}


def test_discovery_progress_for_an_empty_device_is_actionable(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    body = client.get("/api/v1/ekko/candidates?device_id=desk").json()
    assert body["candidates"] == []
    assert body["progress"]["activities"] == 0
    assert "Enroll this device" in body["progress"]["next_step"]


@pytest.fixture
def planning(tmp_path, monkeypatch):
    cfg = _isolate(tmp_path, monkeypatch)
    cfg.write_text(cfg.read_text() + "planning_enabled = true\n")
    config.reset_config_cache()
    store = _enroll(device="desk")
    _seed_recurring_evidence(store)
    candidate = client.get("/api/v1/ekko/candidates?device_id=desk").json()["candidates"][0]
    payload = _review_payload(candidate)
    payload.pop("kind")
    payload["context"] = client.get("/api/v1/ekko/plans?device_id=desk").json()["context"]
    payload.update(stage="shortlisted", expected_revision="", acknowledge_private_storage=True, assumptions={
        "runs_per_week": 10, "manual_minutes": 30, "remaining_minutes": 6, "setup_hours": 3,
    })
    return store, candidate, payload, cfg


def save(candidate, payload):
    return client.put(f"/api/v1/ekko/candidates/{candidate['opportunity_id']}/plan", json=payload)


def test_save_reload_and_revision_conflict_preserve_private_plan(planning):
    store, candidate, payload, _ = planning
    response = save(candidate, payload)
    assert response.status_code == 200, response.text
    plan = response.json()["plan"]
    assert response.json()["started_work"] is False
    assert plan["benefit"]["weekly_hours"] == 4
    assert plan["benefit"]["four_week_hours_after_setup"] == 13
    assert plan["benefit"]["break_even_weeks"] == 0.75
    assert payload["review"]["goal"].encode() not in store.path.read_bytes()
    assert client.get("/api/v1/ekko/plans?device_id=desk").json()["plans"] == [plan]
    payload["review"]["goal"] = "An older tab must not overwrite this"
    assert save(candidate, payload).status_code == 409
    payload["expected_revision"] = plan["revision"]
    assert save(candidate, payload).status_code == 200


def test_pilot_retry_is_idempotent_and_failed_outputs_count_rework(planning):
    _, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    path = f"/api/v1/ekko/plans/{candidate['opportunity_id']}/runs"
    sample = {"device_id": "desk", "context": payload["context"], "expected_revision": plan["revision"],
              "sample_id": "pilot-run-one", "manual_minutes": 30, "remaining_minutes": 6, "accepted": True}
    first = client.post(path, json=sample)
    assert first.status_code == 200, first.text
    assert client.post(path, json=sample).json() == first.json()
    assert first.json()["plan"]["pilot"]["total_minutes_saved"] == 24
    sample.update(sample_id="pilot-run-two", expected_revision=first.json()["plan"]["revision"],
                  remaining_minutes=10, accepted=False)
    second = client.post(path, json=sample).json()["plan"]
    assert second["pilot"] == {"basis": "owner_reported_pilot", "runs": 2,
                               "accepted": 1, "median_minutes_saved": 7, "total_minutes_saved": 14}
    sample["remaining_minutes"] = 2
    assert client.post(path, json=sample).status_code == 409


def test_plans_cannot_cross_owner_device_or_tenant_even_in_shared_database(planning):
    store, candidate, payload, _ = planning
    save(candidate, payload)
    for owner, device, tenant in (("another-person", store.device_id, store.tenant),
                                  (store.owner, "another-device", store.tenant),
                                  (store.owner, store.device_id, "another-workspace")):
        foreign = OpportunityPlans(WorkDiscoveryStore(owner, device, tenant=tenant, path=store.path))
        assert foreign.list() == []
        assert foreign.delete(candidate["opportunity_id"], expected_revision="x" * 32) is False
    assert client.get("/api/v1/ekko/plans?device_id=another-device").json()["plans"] == []


def test_scope_encryption_rejects_ciphertext_transplant(planning):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    foreign = WorkDiscoveryStore("another-person", store.device_id, tenant=store.tenant, path=store.path)
    with store._transaction() as conn:
        blob = conn.execute("SELECT payload FROM ekko_plans").fetchone()[0]
        conn.execute("INSERT INTO ekko_plans VALUES (?,?,?,?,?,?,?)",
                     (*foreign._scope, candidate["opportunity_id"], plan["revision"], blob, plan["expires_at"]))
    with pytest.raises(Exception, match="scope"):
        OpportunityPlans(foreign).list()


def test_expired_plans_and_explicit_source_erasure_remove_notes(planning):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    future = WorkDiscoveryStore(store.owner, store.device_id, tenant=store.tenant,
                                path=store.path, clock=lambda: plan["expires_at"] + 1)
    assert OpportunityPlans(future).list() == []
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ekko_plans").fetchone()[0] == 0


def test_session_erasure_clears_linked_plans(planning):
    store, candidate, payload, _ = planning
    save(candidate, payload)
    store.erase(session_id="repeat-0")
    assert OpportunityPlans(store).list() == []


def test_disabled_planning_keeps_read_and_delete_available(planning):
    _, candidate, payload, cfg = planning
    plan = save(candidate, payload).json()["plan"]
    cfg.write_text(cfg.read_text().replace("planning_enabled = true", "planning_enabled = false"))
    config.reset_config_cache()
    assert save(candidate, payload).status_code == 409
    current = client.get("/api/v1/ekko/plans?device_id=desk").json()
    assert current["plans"]
    deleted = client.request("DELETE", f"/api/v1/ekko/plans/{candidate['opportunity_id']}",
                             json={"device_id": "desk", "context": current["context"], "expected_revision": plan["revision"]})
    assert deleted.status_code == 200 and deleted.json()["removed"]


def test_benefit_math_preserves_unknown_and_negative_outcomes():
    assert BenefitAssumptions().estimate()["weekly_hours"] is None
    assert BenefitAssumptions(10, 30).estimate()["weekly_hours"] is None
    assert BenefitAssumptions(10, 30, 0, 0).estimate()["weekly_hours"] == 5
    assert BenefitAssumptions(10, 5, 8, 2).estimate()["weekly_hours"] == -0.5
    assert BenefitAssumptions(10, 5, 8, 2).estimate()["break_even_weeks"] is None
    assert pilot_summary([])["median_minutes_saved"] is None
    with pytest.raises(ValueError):
        BenefitAssumptions(manual_minutes=float("nan"))


def test_private_save_requires_acknowledgement_and_current_authority(planning, monkeypatch):
    from fastapi import HTTPException

    from maverick_dashboard import auth

    store, candidate, payload, _ = planning
    assert save(candidate, {**payload, "acknowledge_private_storage": False}).status_code == 422
    assert OpportunityPlans(store).list() == []
    plan = save(candidate, payload).json()["plan"]

    def deny(request, permission):
        raise HTTPException(403, "Access removed")

    monkeypatch.setattr(auth, "require_permission", deny)
    assert client.get("/api/v1/ekko/plans?device_id=desk").status_code == 403
    assert save(candidate, {**payload, "expected_revision": plan["revision"]}).status_code == 403
    assert OpportunityPlans(store).list() == [plan]


def test_concurrent_plan_edits_cannot_overwrite_each_other(planning):
    from concurrent.futures import ThreadPoolExecutor

    _, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    edits = [{**payload, "expected_revision": plan["revision"], "stage": stage} for stage in ("pilot", "parked")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda edit: save(candidate, edit), edits))
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response.json()["plan"] for response in responses if response.status_code == 200)
    assert client.get("/api/v1/ekko/plans?device_id=desk").json()["plans"] == [winner]


def test_pilot_is_bounded_and_never_extends_retention(planning):
    _, candidate, payload, _ = planning
    payload["review"]["goal"] = "Private task ✨" * 60
    plan = save(candidate, payload).json()["plan"]
    expires_at = plan["expires_at"]
    path = f"/api/v1/ekko/plans/{candidate['opportunity_id']}/runs"
    for number in range(30):
        sample = {"device_id": "desk", "context": payload["context"], "expected_revision": plan["revision"], "sample_id": f"pilot-run-{number}",
                  "manual_minutes": 30, "remaining_minutes": 6, "accepted": True}
        result = client.post(path, json=sample)
        assert result.status_code == 200, result.text
        plan = result.json()["plan"]
        assert plan["expires_at"] == expires_at
    sample.update(sample_id="pilot-run-limit", expected_revision=plan["revision"])
    assert client.post(path, json=sample).status_code == 422
    assert client.delete("/api/v1/ekko/data?device_id=desk").status_code == 200
    assert client.get("/api/v1/ekko/plans?device_id=desk").json()["plans"] == []


def test_plan_audit_has_no_task_notes_and_failed_audit_rolls_back_save(planning, monkeypatch):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    seen = []
    store.flush_audit_outbox(recorder=lambda kind, **data: seen.append((kind, data)) or True)
    entries = [data for kind, data in seen if kind == "ekko_opportunity_plan"]
    assert len(entries) == 1
    assert entries[0]["lifecycle"]["basis"] == "owner_supplied"
    assert all(value not in str(entries) for value in payload["review"].values())
    monkeypatch.setattr("maverick.work_discovery_store.MAX_AUDIT_OUTBOX", 0)
    payload.update(expected_revision=plan["revision"], stage="pilot")
    assert save(candidate, payload).status_code == 503
    assert OpportunityPlans(store).list() == [plan]
    # Privacy deletion remains available even if audit delivery is blocked.
    assert OpportunityPlans(store).delete(candidate["opportunity_id"], expected_revision=plan["revision"])


def test_plan_save_respects_the_existing_database_size_limit(planning, monkeypatch):
    store, candidate, payload, _ = planning
    monkeypatch.setattr("maverick.work_discovery_store.MAX_DATABASE_BYTES", 1)
    assert save(candidate, payload).status_code == 503
    assert OpportunityPlans(store).list() == []


def test_plan_mutations_reject_stale_workspace_context(planning):
    store, candidate, payload, _ = planning
    stale = save(candidate, {**payload, "context": "0" * 64})
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "ekko_context_changed"
    assert OpportunityPlans(store).list() == []
    plan = save(candidate, payload).json()["plan"]
    path = f"/api/v1/ekko/plans/{candidate['opportunity_id']}"
    stale_revision = {"device_id": "desk", "expected_revision": plan["revision"], "context": "0" * 64}
    assert client.request("DELETE", path, json=stale_revision).status_code == 409
    assert client.post(path + "/runs", json={**stale_revision, "sample_id": "stale-run-one", "manual_minutes": 30,
                                            "remaining_minutes": 6, "accepted": True}).status_code == 409
    assert OpportunityPlans(store).list() == [plan]


@pytest.fixture
def factory(planning):
    _, _, payload, cfg = planning
    cfg.write_text(cfg.read_text() + "build_enabled = true\n[flows]\nenable = true\n")
    config.reset_config_cache()
    payload["context"] = client.get("/api/v1/ekko/plans?device_id=desk").json()["context"]
    return planning


def test_pilot_after_revoked_enrollment_asks_to_enroll_again(planning):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    store.revoke_enrollment()
    response = client.post(f"/api/v1/ekko/plans/{candidate['opportunity_id']}/runs", json={
        "device_id": "desk", "context": payload["context"], "expected_revision": plan["revision"],
        "sample_id": "pilot-run-one", "manual_minutes": 30, "remaining_minutes": 6, "accepted": True})
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == "Your enrollment for this device has ended. Enroll it again to continue."
