"""Undo window for dashboard approvals.

The world model can return a just-decided approval to pending; the consent
consumer waits out ``[approval] undo_grace_seconds`` before acting so an
undo never races an action that already started.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def wm(tmp_path, monkeypatch):
    import maverick.world_model as world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    w = world_model.WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: w)
    yield w
    try:
        w.close()
    except Exception:  # the consent consumer may already have closed it
        pass


def test_undo_round_ids_are_stable_and_distinct():
    from maverick.world_model import _approval_audit_event_id

    base = _approval_audit_event_id("t", 7, "approved", "u:bob")
    assert base == _approval_audit_event_id("t", 7, "approved", "u:bob", 0)
    later = _approval_audit_event_id("t", 7, "approved", "u:bob", 1)
    assert later != base and later != _approval_audit_event_id("t", 7, "approved", "u:bob", 2)


def test_grace_reader_defaults_and_bounds(monkeypatch):
    from maverick.safety import consent

    monkeypatch.delenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert consent.approval_undo_grace_seconds() == 30.0
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "-4")
    assert consent.approval_undo_grace_seconds() == 0.0
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "junk")
    assert consent.approval_undo_grace_seconds() == 30.0
    monkeypatch.setenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", "off")
    assert consent.approval_requires_acknowledgement() is False
    monkeypatch.setenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", "yes")
    assert consent.approval_requires_acknowledgement() is True
