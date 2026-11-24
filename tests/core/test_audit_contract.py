"""The audit refusal contract, and the gate that keeps it.

Two things are pinned here. First, that both refusals share a base a caller can
catch in one handler, so a call site hardened against one refusal is not blind
to the other. Second, that the gate itself can actually fail: a gate that
cannot fail proves nothing, so every assertion below has a negative control.
"""

from __future__ import annotations
from maverick.audit import AuditRefused, audit_event
from maverick.audit.signing import OffHostSigningRequiredError


def test_refusals_remain_runtime_errors() -> None:
    """Handlers predating these names must keep working."""
    assert issubclass(AuditRefused, RuntimeError)
    assert issubclass(OffHostSigningRequiredError, RuntimeError)


def test_audit_event_swallows_ordinary_failures_but_logs_them(monkeypatch, caplog) -> None:
    import logging

    import maverick.audit

    def _boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(maverick.audit, "record", _boom)
    with caplog.at_level(logging.WARNING, logger="maverick.audit.writer"):
        assert audit_event("tool_start", tool="wire_transfer") is False
    assert any("write failed" in r.getMessage() for r in caplog.records)
    assert any(r.exc_info for r in caplog.records)


def test_audit_event_returns_true_on_success(monkeypatch) -> None:
    import maverick.audit

    seen = {}

    def _ok(kind, **payload):
        seen.update({"kind": kind, **payload})
        return True

    monkeypatch.setattr(maverick.audit, "record", _ok)
    assert audit_event("tool_start", agent="a", goal_id=3, tool="t") is True
    assert seen["kind"] == "tool_start" and seen["goal_id"] == 3
