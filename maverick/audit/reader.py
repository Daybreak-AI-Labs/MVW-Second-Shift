"""Single source of truth for reading the tamper-evident audit NDJSON log.

Three read-side consumers share the same three steps here instead of each
re-implementing them with ad-hoc globs and filename literals:

  - :mod:`maverick.audit.export` (SIEM export / ``maverick audit export``),
  - :mod:`maverick.dsar` (GDPR Art. 15/20 subject-access export),
  - :mod:`maverick.soc2` (the audit-chain compliance probe).

They drifted apart in ways that were quietly wrong -- ``dsar`` read the
cross-file ``anchors.ndjson`` tip-ledger as if it were a day-file and ignored
at-rest sealing, while ``export`` excluded the ledger and decrypted sealed
segments. This module defines, once:

  - :func:`day_files` -- what counts as a day-file (re-exported from
    :mod:`maverick.audit.signing`, where the ``YYYY-MM-DD`` pattern and the
    :data:`ANCHOR_FILENAME` constant live), so the anchor ledger is excluded the
    same way everywhere; and
  - :func:`iter_events` -- how to turn the selected day-files into event dicts,
    transparently reading plaintext or authenticated sealed frames, and
    recording malformed/unreadable input in a separate coverage report.

Read-only: nothing here ever mutates the log or touches the signing chain.
"""
from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any
from .segments import ReadReport, SegmentReadError, SegmentSnapshot

log = logging.getLogger(__name__)

__all__ = [
]


def tail_events(path: Path, n: int, *, report: ReadReport | None = None) -> list[dict[str, Any]]:
    """Read a bounded suffix; no claim about unread prefixes or chain proofs."""
    from ..crypto_at_rest import EncryptionUnavailable
    from ..sealed_stream import SealedStreamError

    report = report if report is not None else ReadReport()
    report.scope = "requested_tail"
    out = []
    try:
        if not path.exists():
            return out
        report.segments += 1
        with SegmentSnapshot(path, report) as snapshot:
            for line in snapshot.tail_lines(n):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("non-object audit row")
                except (ValueError, RecursionError):
                    report.problem(path, "invalid_json_object")
                    continue
                out.append(event)
                report.events += 1
        if not report.failures:
            report.completed_segments += 1
    except (OSError, UnicodeError, EncryptionUnavailable, SealedStreamError, SegmentReadError) as error:
        report.problem(path, type(error).__name__)
        log.warning("audit tail incomplete: %s (%s)", path.name, type(error).__name__)
    finally:
        report.finished = True
    return out
