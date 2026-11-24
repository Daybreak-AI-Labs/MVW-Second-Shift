"""A second person approves high-risk requests by default.

``[approval] separate_approver`` is ``"always"`` unless an administrator
changes it: with roles coming from Microsoft Entra, Second Shift cannot always
see who else could approve, so it does not let a requester approve their own
high-risk request on the guess that nobody else could."""
from __future__ import annotations

import time

import pytest

REQUESTER = "user:sam.lee@northwind.example"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_TENANT", "MAVERICK_SEPARATE_APPROVER", "MAVERICK_ALLOW_SELF_APPROVAL",
                 "MAVERICK_APPROVALS_REQUIRED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _park(world, risk: str) -> int:
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="shell", summary="Run one command.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=REQUESTER, workspace="local",
        role="operator", authority_versions={}, input_versions={}, credential_versions={},
        budget={}, expires_at=time.time() + 600, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True)
    return world.create_approval("shell", risk=risk, scope="sandbox:/work",
                                 detail=encode_approval_detail(card), approvals_required=1,
                                 requested_by=REQUESTER)


def test_the_default_is_always():
    from maverick.config_contracts import CHOICE_SETTINGS
    from maverick.safety.dual_control import separate_approver_mode

    assert CHOICE_SETTINGS["approval.separate_approver"].default == "always"
    assert separate_approver_mode() == "always"


def test_a_high_risk_request_cannot_be_approved_by_the_person_who_asked(tmp_path):
    from maverick.channel_approvals import ChannelApprovalRefused, record_vote
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    approval_id = _park(world, "high")
    # Nobody else is known to hold the approver role; the default still refuses.
    with pytest.raises(ChannelApprovalRefused) as refused:
        record_vote(world, approval_id, "approved", REQUESTER)
    assert refused.value.reason == "separate_approver"
    assert refused.value.message == "You asked for this, so someone else must approve it."
    assert world.get_approval(approval_id).status == "pending"


def test_a_low_risk_request_is_not_affected(tmp_path):
    from maverick.channel_approvals import separate_approver_refusal
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    approval_id = _park(world, "low")
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == ""


def test_an_administrator_can_still_choose_the_old_behaviour(tmp_path):
    from maverick import config
    from maverick.channel_approvals import separate_approver_refusal
    from maverick.world_model import WorldModel

    (tmp_path / "config.toml").write_text('[approval]\nseparate_approver = "when_available"\n', encoding="utf-8")
    config.reset_config_cache()
    world = WorldModel(tmp_path / "world.db")
    approval_id = _park(world, "high")
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == ""
