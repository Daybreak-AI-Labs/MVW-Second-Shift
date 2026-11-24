"""Approval decisions from a chat channel share the dashboard's decision path,
carry the same signed audit, confirm twice for High/Critical, refuse what is
expired or decided, and tie chat accounts to Second Shift people."""
from __future__ import annotations

import time

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture
def recorded(monkeypatch):
    import maverick.audit as audit

    rows: list[tuple[str, dict]] = []
    monkeypatch.setattr(audit, "record", lambda kind, **p: rows.append((kind, p)) or True)
    return rows


def _card(action="browser.click", *, expires_in=300.0, irreversible=True, maximum=0.25,
          display_command=None):
    from maverick.approval_cards import build_approval_card

    return build_approval_card(
        action=action, summary="Approve the reviewed customer change",
        target_label="The customer settings page", target={"page": "x"},
        parameters={"secret": "never"},  # pragma: allowlist secret
        parameter_summary=["Press Save once"], actor="user:requester", workspace="t",
        role="operator", authority_versions={"r": "1"}, input_versions={"i": "1"},
        credential_versions={}, budget={"currency": "USD", "maximum": maximum},
        expires_at=time.time() + expires_in, known_effects=["The setting changes."],
        unresolved_assumptions=[], before="Unchanged.", after="Saved.",
        irreversible=irreversible,
        display_command=display_command,
    )


def test_full_length_command_survives_card_round_trip():
    from maverick.approval_cards import decode_approval_detail, encode_approval_detail

    command = "echo " + "x" * 3795
    card = _card(display_command=command)
    assert decode_approval_detail(encode_approval_detail(card))["display"]["command"] == command


def test_dashboard_api_uses_the_shared_audit_delivery():
    from maverick import channel_approvals
    from maverick_dashboard import api

    assert api._audit_approval_decision is channel_approvals.audit_approval_decision


def test_a_queued_action_holding_a_lone_surrogate_is_a_stale_card_not_a_crash():
    from types import SimpleNamespace

    from maverick.approval_cards import encode_approval_detail
    from maverick.channel_approvals import ChannelApprovalRefused, require_current_card

    card = _card()
    approval = SimpleNamespace(detail=encode_approval_detail(card), action="browser.\ud800")
    with pytest.raises(ChannelApprovalRefused) as exc:
        require_current_card(approval, binding=card["binding_sha256"])
    assert exc.value.reason == "stale_card"


def test_the_approval_decision_record_names_its_task(tmp_path, monkeypatch):
    """Live: Activity log rows for approvals had no link to their task."""
    from types import SimpleNamespace

    from maverick import audit
    from maverick.channel_approvals import deliver_approval_audit_event
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("Write a welcome note")
    from maverick.logging_config import _goal_id_var

    token = _goal_id_var.set(goal_id)
    try:
        approval_id = world.create_approval("Run one Python script")
    finally:
        _goal_id_var.reset(token)
    assert world.get_approval(approval_id).goal_id == goal_id
    seen = {}
    monkeypatch.setattr(audit, "audit_event", lambda kind, **fields: seen.update(kind=kind, **fields) or True)
    monkeypatch.setattr(world, "mark_approval_audit_delivered", lambda *a, **k: True)
    event = SimpleNamespace(delivered_at=None, event_id="e" * 32, approval_id=approval_id, status="approved",
                            decided_by="user:chris", created_at=1.0, final_status="approved")
    assert deliver_approval_audit_event(world, event)
    assert seen["kind"] == audit.EventKind.APPROVAL_DECISION and seen["goal_id"] == goal_id
