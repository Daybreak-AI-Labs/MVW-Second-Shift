"""Tests for the audit log writer (maverick.audit.writer): event shape,
redaction depth and tail/grep robustness.
"""
from __future__ import annotations

import json


def test_audit_log_unsigned_by_default(tmp_path):
    import json

    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    adir = tmp_path / "audit"
    alog = AuditLog(adir, sign=False)
    alog.record(AuditEvent(ts=1.0, kind="x", agent="a", payload={}))
    row = json.loads(list(adir.glob("*.ndjson"))[0].read_text().splitlines()[0])
    assert "sig" not in row and "hash" not in row


def test_redaction_does_not_leak_secret_past_depth_64():
    from maverick.audit.writer import _redact_event
    v: object = {"k": "sk-ant-api03-SECRETKEYBODY1234567890abcdef"}  # pragma: allowlist secret
    for _ in range(70):
        v = {"n": v}
    out = json.dumps(_redact_event({"kind": "tool_result", "payload": v}))
    assert "SECRETKEYBODY" not in out


def test_audit_tail_survives_deeply_nested_line(tmp_path):
    from datetime import datetime, timezone

    from maverick.audit.writer import AuditLog
    # tail()/grep() default to today's UTC day-file, so name the fixture for
    # today rather than a fixed date (a hard-coded date only passes on that day).
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    f = tmp_path / f"{day}.ndjson"
    # Deep enough to exhaust json's recursion-descent parser on every CPython
    # (3.11 trips near the 1000 default; 3.12+ near its C-recursion cap, which
    # let a 2000-deep line parse fine and broke an exact-equality assert here).
    depth = 100_000
    f.write_text('{"v":1,"kind":"goal_start"}\n' + ("[" * depth) + ("]" * depth) + "\n")
    log = AuditLog(tmp_path)
    rows = log.tail(10)            # must not raise RecursionError
    # The valid row survives; where exactly the interpreter gives up on the
    # deep line is version-dependent, so assert no-crash + presence, not shape.
    assert {"v": 1, "kind": "goal_start"} in rows
    assert log.grep("goal_start")  # grep also survives


def test_unreadable_earlier_day_fails_governed_record_instead_of_raising(tmp_path, monkeypatch):
    # record() promises True/False; an undecryptable old day-file scanned for
    # a governed identity must surface as False, not a RuntimeError.
    from maverick.audit import sealing
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.segments import SegmentReadError
    from maverick.audit.writer import AuditLog

    adir = tmp_path / "audit"
    adir.mkdir()
    (adir / "2020-01-01.ndjson").write_text("{}\n")

    def _unreadable(path, *, fail_soft=True):
        raise SegmentReadError(f"cannot decrypt {path}")

    monkeypatch.setattr(sealing, "segment_text", _unreadable)
    alog = AuditLog(adir, sign=False)
    event = AuditEvent(ts=1.0, kind=EventKind.PRIVACY_RECORD_CHANGED, agent="a",
                       payload={"event_id": "evt-1"})
    assert alog.record(event) is False


def test_signing_stays_on_when_audit_section_is_not_a_table(monkeypatch):
    import maverick.config as config
    from maverick.audit.writer import _resolve_signing

    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    monkeypatch.setattr("maverick.security_defaults.secure_by_default", lambda: True)
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"audit": "oops"})
    assert _resolve_signing(None) is True
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"audit": {"sign": "false"}})
    assert _resolve_signing(None) is False
