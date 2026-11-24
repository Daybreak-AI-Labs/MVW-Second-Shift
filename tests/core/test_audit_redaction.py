"""Audit log redaction — secrets in payloads never land on disk in plaintext."""
from __future__ import annotations

import json
from pathlib import Path


def _read_first(path: Path) -> dict:
    return json.loads(path.read_text().splitlines()[0])


def test_anonymous_mode_hashes_principal_bearing_audit_fields(monkeypatch, tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    monkeypatch.setenv("MAVERICK_ANON", "1")

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=6.0,
        kind=EventKind.APPROVAL_DECISION,
        payload={
            "approval_id": 123,
            "status": "approved",
            "decided_by": "user:alice@example.com",
            "principal": "user:bob@example.com",
            "claimed_by": "user:carol@example.com",
            "created_by": "user:dana@example.com",
        },
    ))

    row = _read_first(list(tmp_path.glob("*.ndjson"))[0])
    body = json.dumps(row)
    assert "alice@example.com" not in body
    assert "bob@example.com" not in body
    assert "carol@example.com" not in body
    assert "dana@example.com" not in body
    assert row["decided_by"].startswith("decided_by#")
    assert row["principal"].startswith("principal#")
    assert row["claimed_by"].startswith("claimed_by#")
    assert row["created_by"].startswith("created_by#")
    assert row["approval_id"] == 123
    assert row["status"] == "approved"
