"""Encrypt closed audit day-files at rest (confidentiality for the audit log).

The audit log is *signed* for tamper-evidence (``signing.py``) but is otherwise
plaintext NDJSON on disk -- a confidentiality gap when the events carry sensitive
action detail. This seals **closed** day-files (any date strictly before today) in
place with AES-256-GCM, leaving the file name unchanged: a sealed segment just
holds the encrypted blob instead of NDJSON, detected on read by the seal magic
header. The **current** day-file is never sealed -- live append + the flock'd
signing writer keep operating on plaintext.

Reads stay transparent: :func:`segment_text` decrypts a sealed segment back to its
NDJSON text, so the readers (``export.iter_audit_events``) and the verifier
(``signing.verify_chain`` / the cross-file tip ledger) work on sealed and
plaintext segments alike -- and the hash-chain still verifies, because sealing
only encrypts the bytes, never the signed rows.

Exposed as ``maverick audit seal``; runs only when at-rest encryption is enabled.
"""
from __future__ import annotations

from pathlib import Path

from ..file_lock import atomic_read_bytes, ensure_private_directory, ensure_private_file
from .segments import SegmentReadError


def segment_text(path: Path, *, fail_soft: bool = True) -> str:
    """Return an audit day-file's NDJSON text, transparently decrypting a sealed
    segment.

    Export readers use the default fail-soft mode and receive ``""`` on a
    read/decrypt error. Integrity verifiers must pass ``fail_soft=False`` so
    unreadable or undecryptable signed evidence fails closed instead of being
    mistaken for a valid empty chain.
    """
    try:
        path = Path(path)
        ensure_private_directory(path.parent)
        ensure_private_file(path, 0o600)
        raw = atomic_read_bytes(path)
    except OSError as e:
        if fail_soft:
            return ""
        raise SegmentReadError(f"cannot read audit segment {path}: {e}") from e
    from ..crypto_at_rest import is_sealed, unseal
    if is_sealed(raw):
        try:
            return unseal(raw).decode("utf-8")
        # failure-policy: fail_closed
        except Exception as e:
            if fail_soft:
                return ""
            raise SegmentReadError(f"cannot decrypt sealed audit segment {path}: {e}") from e
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        if fail_soft:
            return ""
        raise SegmentReadError(f"cannot decode audit segment {path}: {e}") from e


__all__ = [
    "SegmentReadError",
    "segment_text",
]
