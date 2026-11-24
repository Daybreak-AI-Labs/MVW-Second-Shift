"""Approval queue page + approve/deny endpoints."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def _world(tmp_path):
    from maverick.world_model import WorldModel
    return WorldModel(tmp_path / "world.db")


def _structured_card(
    *,
    action: str = "browser.click",
    expires_at: float | None = None,
    target_label: str = "<script>target</script>",
) -> dict:
    from maverick.approval_cards import build_approval_card

    return build_approval_card(
        action=action,
        summary="Approve the reviewed customer change",
        target_label=target_label,
        target={"page": "https://customer.test/settings", "selector": "#save"},
        parameters={"secret": "never-render-this"},  # pragma: allowlist secret
        parameter_summary=["Activate the Save button once"],
        actor="user:alice",
        workspace="tenant-a",
        role="operator",
        authority_versions={"role_revision": "role-v1"},
        input_versions={"page_revision": "page-v1"},
        credential_versions={"browser_session_sha256": "a" * 64},
        budget={"currency": "USD", "maximum": 0.25},
        expires_at=expires_at if expires_at is not None else time.time() + 300,
        known_effects=["Changes the reviewed customer setting."],
        unresolved_assumptions=["The page may trigger a notification."],
        before="The setting is unchanged.",
        after="The reviewed setting is saved.",
        irreversible=True,
    )


def test_legacy_approval_tokens_are_redacted_from_page_and_api(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    token = "ss-rest-" + "A" * 43
    _world(tmp_path).create_approval(
        f"click {token}",
        risk="high",
        scope=f'input[value="{token}"]',
        detail=f"legacy detail contains {token}",
    )
    client = _client()

    page = client.get("/approvals").text
    body = client.get("/api/v1/approvals").text

    assert token not in page
    assert token not in body
    assert "REDACTED:second_shift_agent_token" in page
    assert "REDACTED:second_shift_agent_token" in body


def test_legacy_approve_is_blocked_but_deny_remains_available(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    w = _world(tmp_path)
    aid = w.create_approval("mass-dm", risk="high")
    client = _client()

    r = client.post(
        f"/api/v1/approvals/{aid}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 409
    assert "predates exact-operation review" in r.json()["detail"]
    assert w.get_approval(aid).status == "pending"

    deny = client.post(
        f"/api/v1/approvals/{aid}/deny",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert deny.status_code == 204
    assert w.get_approval(aid).status == "denied"
    assert client.get("/api/v1/approvals").json()["approvals"] == []


def test_deny_transitions_state(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    w = _world(tmp_path)
    aid = w.create_approval("force-push", risk="high", scope="main")
    client = _client()

    r = client.post(
        f"/api/v1/approvals/{aid}/deny",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    assert w.get_approval(aid).status == "denied"


def test_approve_unknown_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    r = client.post(
        "/api/v1/approvals/9999/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 404


def test_approvals_api_lists_pending(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    w = _world(tmp_path)
    w.create_approval("rm-rf", risk="high", scope="/x", detail="d")
    client = _client()
    body = client.get("/api/v1/approvals").json()
    assert len(body["approvals"]) == 1
    a = body["approvals"][0]
    assert a["action"] == "rm-rf"
    assert a["risk"] == "high"
    assert a["scope"] == "/x"


def test_decision_is_anchored_in_audit_chain(monkeypatch, tmp_path):
    # A human approve/deny is recorded in the signed audit chain so its
    # integrity doesn't rest on the mutable approvals row alone.
    _isolate(monkeypatch, tmp_path)
    w = _world(tmp_path)
    from maverick.approval_cards import encode_approval_detail

    card = _structured_card(action="wire-funds")
    aid = w.create_approval(
        "wire-funds",
        risk="high",
        detail=encode_approval_detail(card),
    )

    recorded = []
    import maverick.audit as audit
    monkeypatch.setattr(audit, "record",
                        lambda kind, **p: recorded.append((kind, p)) or True)

    client = _client()
    r = client.post(
        f"/api/v1/approvals/{aid}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={
            "Origin": "http://127.0.0.1",
            "X-Second-Shift-Approval-Binding": card["binding_sha256"],
        },
    )
    assert r.status_code == 204

    # The high-risk confirmation is its own plain-language event; the
    # decision itself is anchored exactly once.
    decisions = [(k, p) for k, p in recorded if k == audit.EventKind.APPROVAL_DECISION]
    assert len(decisions) == 1
    kind, payload = decisions[0]
    assert payload["approval_id"] == aid
    assert payload["status"] == "approved"
    assert payload["decided_by"]  # the supervisor identity is attributed


def test_no_audit_event_when_decision_is_a_noop(monkeypatch, tmp_path):
    # A 404 (unknown/already-decided) must NOT emit a decision event.
    _isolate(monkeypatch, tmp_path)
    recorded = []
    import maverick.audit as audit
    monkeypatch.setattr(audit, "record",
                        lambda kind, **p: recorded.append((kind, p)) or True)
    client = _client()
    r = client.post("/api/v1/approvals/999999/deny",
                    headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 404
    assert recorded == []


def test_expired_structured_card_never_mutates_approval(monkeypatch, tmp_path):
    from maverick.approval_cards import encode_approval_detail

    _isolate(monkeypatch, tmp_path)
    w = _world(tmp_path)
    card = _structured_card(expires_at=time.time() - 1)
    aid = w.create_approval(
        "browser.click", risk="high", detail=encode_approval_detail(card),
    )
    response = _client().post(
        f"/api/v1/approvals/{aid}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={
            "Origin": "http://127.0.0.1",
            "X-Second-Shift-Approval-Binding": card["binding_sha256"],
        },
    )
    assert response.status_code == 409
    assert w.get_approval(aid).status == "pending"


def test_view_only_approval_submission_is_audited_without_sensitive_content(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    w = _world(tmp_path)
    aid = w.create_approval(
        "wire-private-acquisition", risk="high", detail="sensitive target",
    )
    from maverick import audit
    from maverick_dashboard import auth

    recorded = []
    monkeypatch.setattr(auth, "has_permission", lambda _request, _permission: False)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:viewer")
    monkeypatch.setattr(
        audit,
        "audit_event",
        lambda kind, **payload: recorded.append((kind, payload)) or True,
    )

    response = _client().post(
        f"/api/v1/approvals/{aid}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={"Origin": "http://127.0.0.1"},
    )

    assert response.status_code == 403
    assert w.get_approval(aid).status == "pending"
    assert len(recorded) == 1
    kind, payload = recorded[0]
    assert kind == audit.EventKind.CAPABILITY_DENIED
    assert payload["principal"] == "user:viewer"
    assert len(payload["resource_sha256"]) == 64
    assert "wire-private-acquisition" not in str(payload)
    assert "sensitive target" not in str(payload)


def test_view_only_submission_stays_pending_when_denial_audit_is_unavailable(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    world = _world(tmp_path)
    approval_id = world.create_approval("publish", risk="high")
    from maverick import audit
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_permission", lambda _request, _permission: False)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:viewer")
    monkeypatch.setattr(audit, "audit_event", lambda *_args, **_kwargs: False)

    response = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={"Origin": "http://127.0.0.1"},
    )

    assert response.status_code == 503
    assert "audit receipt is unavailable" in response.json()["detail"]
    assert world.get_approval(approval_id).status == "pending"


@pytest.mark.parametrize("verb,status", [("approve", "approved"), ("deny", "denied")])
def test_decision_routes_run_the_blocking_decision_in_a_worker_thread(monkeypatch, tmp_path, verb, status):
    """The handlers are ``async`` only to read the JSON body. The decision itself
    (database commit, audit signing, cross-process locks) is synchronous and must
    not run on the event loop, where it would stall every other request."""
    import asyncio

    from fastapi import Response
    from fastapi.testclient import TestClient

    from maverick_dashboard import api
    from maverick_dashboard.app import app

    _isolate(monkeypatch, tmp_path)
    approval_id = _world(tmp_path).create_approval("rm-rf", risk="low")
    seen = []

    def decide(request, approval_id, payload, got_status, **_kwargs):
        try:
            asyncio.get_running_loop()
            seen.append("event loop")
        except RuntimeError:
            seen.append("worker thread")
        assert got_status == status
        return Response(status_code=204)

    monkeypatch.setattr(api, "_decide_approval", decide)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.post(f"/api/v1/approvals/{approval_id}/{verb}", json={})
    assert response.status_code == 204, response.text
    assert seen == ["worker thread"]
