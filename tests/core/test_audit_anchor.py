"""Cross-file tip-ledger: deleting/truncating a WHOLE day-file is detectable.

Each YYYY-MM-DD.ndjson is an independent Ed25519 hash-chain,
so per-file ``verify_chain`` can't notice that a whole day-file is *missing*.
``ensure_anchors`` records a signed, chained tip (hash + row count) per completed
day in ``anchors.ndjson``; ``verify_anchors`` confirms every anchored day still
matches. A GDPR erase appends a superseding anchor (no re-sign cascade).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from maverick.audit import signing  # noqa: E402
from maverick.audit.signing import AuditSigner, ensure_anchors


def _isolate_keys(monkeypatch, tmp_path):
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")


def _past_day(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def _write_signed_day(audit_dir, day, n=3):
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for i in range(n):
        signer.write({"kind": "tool_call", "i": i})


def test_unreadable_day_does_not_stop_later_days_being_anchored(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    bad, good = _past_day(2), _past_day(1)
    _write_signed_day(tmp_path, bad, 1)
    _write_signed_day(tmp_path, good, 1)
    real = signing._file_tip_and_count

    def _flaky(path):
        from maverick.audit.segments import SegmentReadError

        if path.stem == bad:
            raise SegmentReadError("cannot decrypt")
        return real(path)

    monkeypatch.setattr(signing, "_file_tip_and_count", _flaky)
    assert ensure_anchors(tmp_path) == 1
    assert signing._anchored_days(tmp_path) == {good}


def test_unsigned_day_is_not_anchored_with_an_empty_tip(tmp_path, monkeypatch):
    # A day written before crypto was installed has no row hashes. An anchor
    # with tip_hash "" is permanent in the append-only ledger and makes WORM
    # reject the whole ledger schema.
    _isolate_keys(monkeypatch, tmp_path)
    unsigned, signed = _past_day(2), _past_day(1)
    (tmp_path / f"{unsigned}.ndjson").write_text('{"kind": "tool_call"}\n')
    _write_signed_day(tmp_path, signed, 1)
    assert ensure_anchors(tmp_path) == 1
    assert signing._anchored_days(tmp_path) == {signed}


def test_highwater_is_not_written_from_a_half_written_ledger_line(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    _write_signed_day(tmp_path, _past_day(2), 1)
    ensure_anchors(tmp_path)
    hw = tmp_path / signing.ANCHOR_HIGHWATER_FILENAME
    before = hw.read_bytes()
    with open(tmp_path / signing.ANCHOR_FILENAME, "a", encoding="utf-8") as f:
        f.write('{"kind": "anchor", "day": "')     # append still in progress
    signing._write_anchor_highwater(tmp_path)
    assert hw.read_bytes() == before
