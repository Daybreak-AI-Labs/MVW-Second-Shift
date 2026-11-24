"""Audit signing-key rotation.

Rotation is safe and additive: the new key becomes the active signer while every
prior public key is retained, so the chain stays verifiable across the rotation
(each row carries its key_id). No audit data is rewritten.
"""
from __future__ import annotations

import pytest

from maverick.audit import signing
from maverick.file_lock import private_path_is_restricted

pytestmark = pytest.mark.usefixtures("local_audit_key_custody")


@pytest.fixture(autouse=True)
def _temp_keys(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    yield


def test_signing_keys_and_audit_file_have_private_custody(tmp_path):
    audit = tmp_path / "audit" / "2026-06-18.ndjson"
    signer = signing.AuditSigner(audit)
    assert signer.write({"event": "custody-check"})

    key_dir = signing._key_dir()
    key_id = (key_dir / "active").read_text(encoding="utf-8")
    assert private_path_is_restricted(audit.parent, 0o700)
    assert private_path_is_restricted(audit, 0o600)
    assert private_path_is_restricted(key_dir, 0o700)
    assert private_path_is_restricted(key_dir / "active", 0o600)
    assert private_path_is_restricted(key_dir / f"{key_id}.key", 0o600)
    assert private_path_is_restricted(key_dir / f"{key_id}.pub", 0o644)


@pytest.mark.parametrize(
    "tail",
    [
        "[]",
        "null",
        '"not-an-object"',
        '{"prev_hash":"","hash":"bad","sig":"' + "0" * 128
        + '","key_id":"0000000000000000"}',
        '{"hash":"' + "0" * 64 + '"}',
    ],
    ids=["array", "null", "string", "bad-hash", "partial-signing-fields"],
)
def test_signer_refuses_non_object_or_invalid_signed_tail(tmp_path, tail):
    audit = tmp_path / "audit" / "2026-06-18.ndjson"
    audit.parent.mkdir(parents=True)
    audit.write_text(tail + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="last line"):
        signing.AuditSigner(audit)


def test_verify_chain_reports_non_object_row_as_malformed(tmp_path):
    audit = tmp_path / "audit" / "2026-06-18.ndjson"
    audit.parent.mkdir(parents=True)
    audit.write_text("[]\n", encoding="utf-8")

    breaks = signing.verify_chain(audit)
    assert len(breaks) == 1
    assert breaks[0].reason == "malformed"


def test_verify_chain_reports_non_string_signing_fields_as_malformed(tmp_path):
    audit = tmp_path / "audit" / "2026-06-18.ndjson"
    audit.parent.mkdir(parents=True)
    audit.write_text(
        '{"prev_hash":"","hash":[],"sig":"00","key_id":"0000000000000000"}\n',
        encoding="utf-8",
    )

    breaks = signing.verify_chain(audit)
    assert len(breaks) == 1
    assert breaks[0].reason == "malformed"


def test_signer_rejects_mismatched_private_and_public_key(tmp_path):
    _priv, _pub, key_id = signing._load_or_create_keypair()
    other_priv, _other_pub, _other_id = signing._generate_keypair()
    signing.atomic_write_bytes(
        signing._key_dir() / f"{key_id}.key",
        other_priv,
        mode=0o600,
    )

    with pytest.raises(ValueError, match="private/public signing key files do not match"):
        signing.AuditSigner(tmp_path / "audit" / "2026-06-18.ndjson")
    with pytest.raises(ValueError, match="private/public signing key files do not match"):
        signing.trusted_audit_public_keys()
