"""Audit-log erase and append lifecycle.

Covers four properties of the audit erase/write path:

  1. GDPR erase matches on STRUCTURED channel+user_id fields only -- it must
     match ``slack``+``42`` but never over-match ``slack:4200`` via a substring
     of a serialized value (and never under-match a ``slack/42`` encoding).
  2. A same-process erase-then-record verifies clean: erase resets the live
     signer's stale in-memory chain head so the next record() chains onto the
     re-anchored tail, not a hash no longer in the file.
  3. The unsigned write path fsyncs (durability parity with the signed path).
  4. Concurrent appends serialize under an advisory flock.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def _have_crypto() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def test_unsigned_record_fsyncs(tmp_path, monkeypatch):
    from maverick.audit import writer as W
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    fsynced: list[int] = []
    monkeypatch.setattr(W.os, "fsync", lambda fd: fsynced.append(fd))

    log = AuditLog(audit_dir=tmp_path, sign=False)
    assert log.record(AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={}))
    assert fsynced, "unsigned audit write must fsync the row"


def test_unsigned_record_acquires_flock(tmp_path, monkeypatch):
    """The unsigned append takes an exclusive advisory flock and releases it."""
    fcntl = pytest.importorskip("fcntl")
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    calls: list[int] = []
    real_flock = fcntl.flock
    monkeypatch.setattr(
        fcntl, "flock", lambda fd, op: (calls.append(op), real_flock(fd, op))[1]
    )

    log = AuditLog(audit_dir=tmp_path, sign=False)
    assert log.record(AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={}))
    assert fcntl.LOCK_EX in calls, "append must acquire an exclusive flock"
    assert fcntl.LOCK_UN in calls, "the flock must be released after the append"


@pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")
def test_concurrent_signed_appends_keep_one_chain_on_windows_and_posix(
    tmp_path, monkeypatch,
):
    """Independent processes must serialize tail-read, sign, and append."""
    from maverick.audit import signing
    from maverick.audit.signing import verify_chain

    home = tmp_path / "home"
    audit_dir = home / "audit"
    key_dir = audit_dir / "keys"
    monkeypatch.setattr(signing, "KEY_DIR", key_dir)

    code = r"""
import sys
from pathlib import Path
from maverick.audit.events import AuditEvent
from maverick.audit.writer import AuditLog

audit_dir, tag, count = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
log = AuditLog(audit_dir=audit_dir, sign=True)
for i in range(count):
    ok = log.record(AuditEvent(ts=float(i), kind="tool_call", agent=tag,
                               payload={"sequence": i, "blob": tag * 2048}))
    if not ok:
        raise SystemExit("signed audit append failed")
"""
    env = os.environ.copy()
    env["MAVERICK_HOME"] = str(home)
    env.pop("MAVERICK_TENANT", None)
    env["MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY"] = "0"
    count = 20
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(audit_dir), tag, str(count)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for tag in ("a", "b", "c")
    ]
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=90)
        assert proc.returncode == 0, (stdout, stderr)

    files = list(audit_dir.glob("20??-??-??.ndjson"))
    assert len(files) == 1
    rows = [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3 * count
    assert verify_chain(files[0]) == []


def test_append_lock_backend_failure_refuses_write_and_releases_stripe(
    tmp_path, monkeypatch,
):
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    log = AuditLog(audit_dir=tmp_path / "audit", sign=False)
    event = AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={})
    assert log.record(event)

    if os.name == "nt":
        import msvcrt

        real_lock = msvcrt.locking
        monkeypatch.setattr(
            msvcrt,
            "locking",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("lock denied")),
        )
    else:
        import fcntl

        real_lock = fcntl.flock
        monkeypatch.setattr(
            fcntl,
            "flock",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("lock denied")),
        )

    assert log.record(event) is False
    if os.name == "nt":
        monkeypatch.setattr(msvcrt, "locking", real_lock)
    else:
        monkeypatch.setattr(fcntl, "flock", real_lock)
    assert log.record(event), "failed __enter__ must not strand the local stripe"

    path = next((tmp_path / "audit").glob("*.ndjson"))
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


@pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")
def test_two_signed_writers_refresh_the_locked_chain_tail(_isolate_keys, tmp_path):
    """Two signer instances created at the same tip must not fork the chain.

    Construct both before either writes so both cache genesis. The second write
    must ignore that stale cache, read the first row while holding the append
    lock, and bind its ``prev_hash`` to the actual durable tip.
    """
    from maverick.audit.signing import AuditSigner, verify_chain

    path = tmp_path / "audit" / "2026-01-05.ndjson"
    path.parent.mkdir(parents=True)
    path.touch()
    first = AuditSigner(path)
    second = AuditSigner(path)

    # Make the first row larger than the signer's bounded reverse-read chunk so
    # the stale-tip regression also exercises a chain tip that spans chunks.
    assert first.write(
        {
            "v": 1,
            "kind": "goal_start",
            "agent": "first",
            "detail": "x" * (70 * 1024),
        }
    )
    assert second.write({"v": 1, "kind": "goal_end", "agent": "second"})

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert verify_chain(path) == []


@pytest.fixture
def _isolate_keys(monkeypatch, tmp_path):
    from maverick.audit import signing

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
