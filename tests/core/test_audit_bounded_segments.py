"""Actual bounded readers, framed history, and truthful evidence coverage."""
from __future__ import annotations

import json
import os

import pytest

from maverick import crypto_at_rest as crypto
from maverick.audit import signing
from maverick.audit.reader import tail_events
from maverick.audit.segments import READ_CHUNK, ReadReport, SegmentReadError, SegmentSnapshot
from maverick.file_lock import atomic_write_bytes, atomic_write_bytes_chunks, open_private_read


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "11" * 32)
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "fixture.key")
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "signing-keys")


def test_large_live_tail_reads_only_suffix_and_exact_last_records(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    rows = 25000
    atomic_write_bytes_chunks(path, ((json.dumps({"i": i, "data": "x" * 700}) + "\n").encode() for i in range(rows)))
    report = ReadReport()
    result = tail_events(path, 20, report=report)
    assert [e["i"] for e in result] == list(range(rows - 20, rows))
    assert report.bytes_read <= READ_CHUNK + 8
    assert report.state == "readable_complete"
    assert report.scope == "requested_tail"
    assert report.verification == "not_requested"


def test_partial_live_tail_reports_truncated_final_record(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n{"i":2}\n{"i":')
    report = ReadReport()
    assert tail_events(path, 2, report=report) == [{"i": 1}, {"i": 2}]
    assert report.state == "partial"


def test_source_replacement_or_append_is_reported_after_snapshot(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n')
    with SegmentSnapshot(path, ReadReport()) as snapshot:
        with path.open("ab") as output:
            output.write(b'{"i":2}\n')
        with pytest.raises(SegmentReadError, match="changed"):
            list(snapshot.lines())


def test_same_size_same_timestamp_change_between_proof_and_export_is_detected(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n')
    with SegmentSnapshot(path, ReadReport()) as snapshot:
        assert list(snapshot.lines()) == ['{"i":1}\n']
        before = path.stat()
        path.write_bytes(b'{"i":2}\n')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with pytest.raises(SegmentReadError, match="between verification"):
            list(snapshot.lines())


def test_private_stream_reader_refuses_hardlink_without_reading(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"sensitive")
    target = tmp_path / "audit" / "2020-01-01.ndjson"
    target.parent.mkdir()
    os.link(original, target)
    with pytest.raises(PermissionError):
        open_private_read(target)
