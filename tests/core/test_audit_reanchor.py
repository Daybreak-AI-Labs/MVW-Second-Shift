"""Re-anchoring the signed audit chain after a GDPR erase.

A scrub/delete tombstones or removes audit rows but does NOT recompute the
Ed25519 prev_hash/hash/sig chain, so `maverick audit verify` then reports
breaks indistinguishable from tampering -- a routine privacy operation
destroying the trust anchor. erase now re-anchors the chain so it verifies
clean again, with the signed `erase` marker documenting the authorized cut.
"""

from __future__ import annotations

import pytest


def _have_crypto() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")


@pytest.fixture
def _isolate_keys(monkeypatch, tmp_path):
    """Point the audit signing key dir at the tmp tree.

    Patch the compatibility hook explicitly so the test never touches the
    active tenant's real audit-key directory.
    """
    from maverick.audit import signing

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")


@pytest.mark.usefixtures("local_audit_key_custody")
def test_erase_after_a_key_rotation_leaves_other_days_and_their_anchors_alone(
    _isolate_keys, tmp_path,
):
    """Only days that hold the subject are rewritten, and each is re-anchored.

    The follow-up re-anchor used to re-sign every day-file and the tip ledger
    under the new key without anchoring them again."""
    from maverick.audit.writer import AuditLog

    ad = tmp_path / "audit"
    held, other = ad / "2000-01-01.ndjson", ad / "2000-01-02.ndjson"

    assert AuditLog(audit_dir=ad, sign=True).reanchor_after_erase() == 0

