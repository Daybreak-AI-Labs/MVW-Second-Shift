"""Enterprise mode: egress lock + fail-closed safety defaults."""
from __future__ import annotations

import pytest
from maverick import capability
from maverick.enterprise import enterprise_enabled


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Start each test from a known-off state with an empty config."""
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.delenv("MAVERICK_PROFILE", raising=False)
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_off_by_default():
    assert enterprise_enabled() is False


def test_env_enables_and_disables(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert enterprise_enabled() is True
    # An explicit falsey env force-disables even if config would enable it.
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    assert enterprise_enabled() is False


def test_config_enables(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"enterprise": {"mode": True}}
    )
    assert enterprise_enabled() is True


def test_policy_uncertainty_fails_closed(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "maybe")
    assert enterprise_enabled() is True

    monkeypatch.delenv("MAVERICK_ENTERPRISE")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"mode": "false"}},
    )
    assert enterprise_enabled() is True


def test_unreadable_config_source_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.config_source_errors",
        lambda **_kwargs: {"config.toml": "unreadable"},
    )
    assert enterprise_enabled() is True


def test_capabilities_forced_on_in_enterprise(monkeypatch):
    assert capability.capability_enforced() is False
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert capability.capability_enforced() is True


def test_enterprise_recognizes_affirmatives_and_negatives(monkeypatch):
    from maverick import enterprise
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    for v in ("1", "true", "on", "yes", "enable", "enabled", "y", "t"):
        monkeypatch.setenv("MAVERICK_ENTERPRISE", v)
        assert enterprise.enterprise_enabled() is True, v
    for v in ("0", "false", "off", "no", "disable", "disabled"):
        monkeypatch.setenv("MAVERICK_ENTERPRISE", v)
        assert enterprise.enterprise_enabled() is False, v


def test_enterprise_ambiguous_env_falls_through_to_config(monkeypatch):
    from maverick import enterprise
    # An unrecognized env value must NOT silently disable the control: config decides.
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"enterprise": {"mode": True}})
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "enabled-for-prod")
    assert enterprise.enterprise_enabled() is True
