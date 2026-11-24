"""N-of-M dual control (segregation of duties) over the approvals queue."""
from __future__ import annotations

import pytest

from maverick.safety import dual_control
from maverick.world_model import WorldModel


@pytest.fixture
def wm(tmp_path):
    return WorldModel(tmp_path / "w.db")


def test_required_approvals_default_is_one(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg", dict)
    assert dual_control.required_approvals("high") == 1


def test_required_approvals_global_int(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg",
                        lambda: {"approvals_required": 2})
    assert dual_control.required_approvals("low") == 2


def test_required_approvals_per_risk_table(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg",
                        lambda: {"approvals_required": {"high": 2, "critical": 3,
                                                        "default": 1}})
    assert dual_control.required_approvals("critical") == 3
    assert dual_control.required_approvals("high") == 2
    assert dual_control.required_approvals("medium") == 1   # falls to default


def test_required_approvals_env_wins(monkeypatch):
    monkeypatch.setattr(dual_control, "_security_cfg",
                        lambda: {"approvals_required": 5})
    monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", "2")
    assert dual_control.required_approvals("high") == 2


def test_per_risk_minimums_only_add_approvers(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg", lambda: {
        "approvals_required": 2,
        "approvals_required_by_risk": {"critical": 4, "low": 1},
    })
    assert dual_control.required_approvals("critical") == 4
    assert dual_control.required_approvals("low") == 2   # never fewer than the base
    assert dual_control.required_approvals("high") == 2
    monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", "3")
    assert dual_control.required_approvals("critical") == 3  # the environment still wins


def test_unparseable_env_does_not_lower_the_configured_quorum(monkeypatch):
    monkeypatch.setattr(dual_control, "_security_cfg", lambda: {"approvals_required": 2})
    for value in ("two", "0", "-1"):
        monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", value)
        assert dual_control.required_approvals("high") == 2, value


def test_unparseable_configured_quorum_requires_two_approvers(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    for value in ("two", 0, -3, True, {"high": "two"}, {"default": 0}):
        monkeypatch.setattr(dual_control, "_security_cfg",
                            lambda value=value: {"approvals_required": value})
        assert dual_control.required_approvals("high") == 2, value
    monkeypatch.setattr(dual_control, "_security_cfg", lambda: {
        "approvals_required": 3, "approvals_required_by_risk": {"high": "x"}})
    assert dual_control.required_approvals("high") == 3  # never lowered


def test_allow_self_approval_default_false(monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg", dict)
    assert dual_control.allow_self_approval() is False
    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "1")
    assert dual_control.allow_self_approval() is True


def test_approval_state_unknown_is_none(wm):
    assert wm.approval_state(99999) is None
