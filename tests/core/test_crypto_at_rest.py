"""Encryption at rest: AES-256-GCM seal/unseal + key management."""
from __future__ import annotations

import base64
import importlib.util

import pytest

from maverick import crypto_at_rest as car
from maverick import file_lock

# AES-GCM needs the optional 'cryptography' extra; skip only the tests that
# exercise encryption where it is absent, matching the audit-signing tests
# (test_audit_anchor.py). Key-management tests still run without the extra.
requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_ENCRYPT_AT_REST", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.delenv("MAVERICK_REPLICA_COUNT", raising=False)
    monkeypatch.delenv("MAVERICK_GOVERNED_RECORDS_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.load_governed_records_config", dict)
    monkeypatch.setattr(
        "maverick.config.governed_records_config_source_errors",
        dict,
    )
    # Keep the generated key out of the real ~/.maverick.
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")


def test_default_follows_the_posture():
    # Unset flag: sealed under the secure default, plaintext in legacy mode.
    from maverick.security_defaults import secure_by_default

    assert car.at_rest_enabled() is secure_by_default()


def test_enabled_by_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert car.at_rest_enabled() is True
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    assert car.at_rest_enabled() is False


def test_natural_truthy_tokens_enable_not_disable(monkeypatch):
    # Regression: a natural affirmative like 'on'/'yes'/'enabled'/'true' must
    # ENABLE at-rest encryption, not silently disable it (which stored plaintext).
    for tok in ("on", "yes", "enabled", "enable", "true", "y", "TRUE", " On "):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", tok)
        assert car.at_rest_enabled() is True, f"{tok!r} should enable encryption"


def test_at_rest_floor_fails_safe_on_unrecognized_value(monkeypatch):
    # An unrecognised value must keep the security floor ON (fail-safe), never
    # silently downgrade to plaintext. Only an EXPLICIT false token disables.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "garbage")
    assert car.at_rest_enabled() is True
    for tok in ("0", "false", "off", "disabled", "no"):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", tok)
        assert car.at_rest_enabled() is False, f"{tok!r} should disable encryption"


def test_implied_by_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert car.at_rest_enabled() is True


def test_config_enables(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"encryption": {"at_rest": True}}
    )
    assert car.at_rest_enabled() is True


@requires_crypto
def test_seal_unseal_roundtrip():
    secret = b"patient SSN 123-45-6789"
    blob = car.seal(secret)
    assert car.is_sealed(blob)
    assert blob != secret  # actually encrypted
    assert b"123-45-6789" not in blob  # plaintext not present in ciphertext
    assert car.unseal(blob) == secret


def test_unseal_passthrough_for_plaintext():
    # A blob without the magic header is legacy plaintext -> returned as-is.
    assert car.unseal(b"plain old note") == b"plain old note"
    assert car.is_sealed(b"plain old note") is False


@requires_crypto
def test_each_seal_uses_fresh_nonce():
    a, b = car.seal(b"same"), car.seal(b"same")
    assert a != b  # nonce randomization -> distinct ciphertexts
    assert car.unseal(a) == car.unseal(b) == b"same"


@requires_crypto
def test_tamper_is_detected():
    blob = bytearray(car.seal(b"important"))
    blob[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(Exception):  # noqa: B017 - InvalidTag from the AEAD
        car.unseal(bytes(blob))


@requires_crypto
def test_injected_key_hex_and_base64(monkeypatch):
    key = bytes(range(32))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    blob = car.seal(b"x")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", base64.b64encode(key).decode())
    assert car.unseal(blob) == b"x"  # same key, different encoding -> opens


@requires_crypto
def test_injected_key_wrong_size_fails(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "00" * 16)  # 16 bytes, not 32
    with pytest.raises(car.EncryptionUnavailable):
        car.seal(b"x")


@requires_crypto
def test_generated_key_persists_and_chmod(monkeypatch):
    blob = car.seal(b"persist me")
    assert car._KEY_PATH.exists()
    assert file_lock.private_path_is_restricted(car._KEY_PATH)
    assert file_lock.private_path_is_restricted(car._KEY_PATH.parent, 0o700)
    # A second seal reuses the same on-disk key, so unseal still works.
    assert car.unseal(blob) == b"persist me"


def test_generated_key_is_created_private_atomically(monkeypatch):
    original_create = file_lock.atomic_create_text
    observed = {}

    def checked_create(path, text, *, mode=0o600, encoding="utf-8"):
        observed["target_absent"] = not car._KEY_PATH.exists()
        observed["requested_mode"] = mode
        observed["parent_private_before_create"] = (
            file_lock.private_path_is_restricted(car._KEY_PATH.parent, 0o700)
        )
        return original_create(path, text, mode=mode, encoding=encoding)

    monkeypatch.setattr(file_lock, "atomic_create_text", checked_create)

    car._load_or_create_key()

    assert observed == {
        "target_absent": True,
        "requested_mode": 0o600,
        "parent_private_before_create": True,
    }
    assert file_lock.private_path_is_restricted(car._KEY_PATH)
    before = car._KEY_PATH.read_text(encoding="utf-8")
    monkeypatch.setattr(file_lock, "atomic_create_text", original_create)
    with pytest.raises(FileExistsError):
        car._write_new_key_file(b"z" * 32)
    assert car._KEY_PATH.read_text(encoding="utf-8") == before
    assert not list(car._KEY_PATH.parent.glob(".at_rest.key-*.tmp"))


def test_existing_key_permissions_are_repaired_before_read(monkeypatch):
    car._KEY_PATH.parent.mkdir(parents=True)
    car._KEY_PATH.write_text((b"k" * 32).hex(), encoding="utf-8")
    if car.os.name != "nt":
        car._KEY_PATH.parent.chmod(0o755)
        car._KEY_PATH.chmod(0o644)
    original_read_text = file_lock.atomic_read_text
    observed = {}

    def checked_read_text(path, *args, **kwargs):
        if path == car._KEY_PATH:
            observed["key_private_before_read"] = (
                file_lock.private_path_is_restricted(path)
            )
            observed["parent_private_before_read"] = (
                file_lock.private_path_is_restricted(path.parent, 0o700)
            )
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_read_text", checked_read_text)

    assert car._load_or_create_key() == b"k" * 32
    assert observed == {
        "key_private_before_read": True,
        "parent_private_before_read": True,
    }


@requires_crypto
def test_seal_to_str_roundtrip_and_passthrough():
    tok = car.seal_to_str("hello secret")
    assert tok.startswith("MVKAR1:")
    assert "hello secret" not in tok
    assert car.unseal_from_str(tok) == "hello secret"
    # Legacy plaintext (no marker) passes through unchanged.
    assert car.unseal_from_str("plain value") == "plain value"
    assert car.is_sealed_str(tok) and not car.is_sealed_str("plain value")


@requires_crypto
def test_unseal_many_from_str_reuses_one_key_resolution(monkeypatch):
    tokens = [car.seal_to_str(f"secret-{i}") for i in range(4)]
    original = car._load_or_create_key
    calls = 0

    def counted_load():
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(car, "_load_or_create_key", counted_load)

    assert car.unseal_many_from_str([tokens[0], "legacy", *tokens[1:]]) == [
        "secret-0", "legacy", "secret-1", "secret-2", "secret-3",
    ]
    assert calls == 1


def test_unseal_from_str_treats_marker_collisions_as_plaintext():
    invalid_b64 = "MVKAR1:A"
    decoded_without_magic = "MVKAR1:" + base64.b64encode(b"Hello").decode("ascii")
    decoded_truncated_magic = "MVKAR1:" + base64.b64encode(car._MAGIC).decode("ascii")

    assert car.unseal_from_str(invalid_b64) == invalid_b64
    assert car.unseal_from_str(decoded_without_magic) == decoded_without_magic
    assert car.unseal_from_str(decoded_truncated_magic) == decoded_truncated_magic
    assert not car.is_sealed_str(invalid_b64)
    assert not car.is_sealed_str(decoded_without_magic)
    assert not car.is_sealed_str(decoded_truncated_magic)


@requires_crypto
def test_unseal_from_str_rejects_tampered_sealed_payload():
    blob = bytearray(car.seal(b"important"))
    blob[-1] ^= 0x01
    tok = "MVKAR1:" + base64.b64encode(bytes(blob)).decode("ascii")

    with pytest.raises(Exception):  # noqa: B017 - InvalidTag from the AEAD
        car.unseal_from_str(tok)


def _per_tenant_env(monkeypatch, tmp_path, tenant="acme"):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)  # deterministic 32-byte KEK
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    if tenant is not None:
        monkeypatch.setenv("MAVERICK_TENANT", tenant)
    else:
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.tenant import kms as tenant_kms
    tenant_kms._clear_cache()


def test_per_tenant_off_by_default():
    assert car.per_tenant_at_rest() is False


def test_per_tenant_enabled_by_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    assert car.per_tenant_at_rest() is True
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    assert car.per_tenant_at_rest() is False


def test_per_tenant_enabled_by_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"encryption": {"per_tenant": True}},
    )
    assert car.per_tenant_at_rest() is True


def test_tenant_magic_matches_tenant_kms():
    # The duplicated header constant must stay in lock-step with tenant_kms.
    from maverick.tenant import kms as tenant_kms
    assert car._TENANT_MAGIC == tenant_kms._SEAL_MAGIC


@requires_crypto
def test_per_tenant_seal_uses_tenant_envelope(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="acme")
    blob = car.seal(b"tenant secret 42")
    assert blob[: len(car._TENANT_MAGIC)] == car._TENANT_MAGIC
    assert car.is_sealed(blob)
    assert b"tenant secret 42" not in blob
    assert car.unseal(blob) == b"tenant secret 42"


@requires_crypto
def test_per_tenant_seal_uses_raw_tenant_id_for_kms(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="slack:alice")
    seen = {}

    def fake_seal_for_tenant(tenant_id, plaintext):
        seen["tenant_id"] = tenant_id
        seen["plaintext"] = plaintext
        return car._TENANT_MAGIC + b"fake"

    monkeypatch.setattr("maverick.tenant.kms.seal_for_tenant", fake_seal_for_tenant)
    assert car.seal(b"secret") == car._TENANT_MAGIC + b"fake"
    assert seen == {"tenant_id": "slack:alice", "plaintext": b"secret"}


@requires_crypto
def test_per_tenant_unseal_uses_raw_tenant_id_for_kms(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="slack:alice")
    seen = {}

    def fake_unseal_for_tenant(tenant_id, blob):
        seen["tenant_id"] = tenant_id
        seen["blob"] = blob
        return b"secret"

    monkeypatch.setattr("maverick.tenant.kms.unseal_for_tenant", fake_unseal_for_tenant)
    blob = car._TENANT_MAGIC + b"fake"
    assert car.unseal(blob) == b"secret"
    assert seen == {"tenant_id": "slack:alice", "blob": blob}


@requires_crypto
def test_per_tenant_text_column_helpers(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="acme")
    tok = car.seal_to_str("invoice total")
    assert tok.startswith("MVKAR1:")        # TEXT-column wrapper is unchanged
    assert "invoice total" not in tok
    assert car.is_sealed_str(tok)
    assert car.unseal_from_str(tok) == "invoice total"


@requires_crypto
def test_global_sealed_data_still_opens_after_per_tenant_on(monkeypatch, tmp_path):
    # Data sealed with the process-wide key (per-tenant OFF) must keep opening
    # once per-tenant mode is switched on — reads auto-detect by magic header.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    legacy = car.seal(b"sealed before the switch")
    assert legacy[: len(car._MAGIC)] == car._MAGIC

    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    from maverick.tenant import kms as tenant_kms
    tenant_kms._clear_cache()
    assert car.unseal(legacy) == b"sealed before the switch"


@requires_crypto
def test_one_tenant_cannot_open_anothers_data(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="acme")
    blob = car.seal(b"acme only")
    from maverick.tenant import kms as tenant_kms
    # Re-pin to a different tenant; the GCM context no longer matches.
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    tenant_kms._clear_cache()
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(blob)


@requires_crypto
def test_unseal_wrong_key_or_tamper_raises_encryption_unavailable(monkeypatch, tmp_path):
    """unseal() honors its documented contract: a genuinely-sealed blob that
    can't be opened (tampered, wrong key, or truncated) raises
    EncryptionUnavailable, not a leaking cryptography InvalidTag / ValueError."""
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "k.key")

    blob = car.seal(b"secret data")
    # Tampered GCM tag.
    bad = bytearray(blob)
    bad[-1] ^= 0xFF
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(bytes(bad))
    # Truncated (no room for nonce + tag).
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(car._MAGIC + b"short")
    # A clean round-trip still works.
    assert car.unseal(blob) == b"secret data"


@requires_crypto
@requires_crypto
def test_a_read_never_creates_a_missing_key(tmp_path):
    blob = car.seal(b"hello")
    key_path = tmp_path / "keys" / "at_rest.key"
    key_path.unlink()
    with pytest.raises(car.EncryptionUnavailable, match="missing"):
        car.unseal(blob)
    assert not key_path.exists()


@requires_crypto
def test_a_stray_keyring_file_is_not_an_active_key(tmp_path):
    ring = tmp_path / "keys" / "at_rest.d"
    ring.mkdir(parents=True)
    (ring / "backup.key").write_text("00" * 32)
    (ring / "ab.key").write_text("00" * 32)
    (ring / "ABCDEF0123456789.key").write_text("00" * 32)  # lookup is lower-case
    blob = car.seal(b"x")
    assert car.unseal(blob) == b"x"


def test_no_keyring_keeps_v1_format():
    # With no keyring, seal() produces the legacy v1 header (no behaviour change).
    blob = car.seal(b"hello")
    assert blob[: len(car._MAGIC)] == car._MAGIC
    assert car.unseal(blob) == b"hello"


def test_keygen_logs_backup_warning(monkeypatch, caplog):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    import logging
    with caplog.at_level(logging.WARNING, logger="maverick.crypto_at_rest"):
        car._load_or_create_key()
    assert any("only way to decrypt" in r.message or "backup-key" in r.message
               for r in caplog.records)


def test_key_path_is_deployment_wide_not_request_scoped(tmp_path, monkeypatch):
    """One key per deployment: a request bound to a workspace must seal with
    the same key every other scope reads with (a row sealed inside a
    tenant-bound request was unreadable to the owner-invite flow otherwise).
    MAVERICK_TENANT, a deployment-level binding, still picks the directory."""
    from maverick.paths import reset_tenant, set_tenant

    home = tmp_path / "home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setattr(car, "_KEY_PATH", None)   # the production default

    unbound = car._key_path()
    tok = set_tenant("tenant-a")
    try:
        path_a = car._key_path()
    finally:
        reset_tenant(tok)
    tok = set_tenant("tenant-b")
    try:
        path_b = car._key_path()
    finally:
        reset_tenant(tok)
    assert unbound == path_a == path_b == home / "keys" / "at_rest.key"

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-env")
    bound = car._key_path()
    assert "tenant-env" in str(bound) and bound.name == "at_rest.key"
    tok = set_tenant("tenant-a")
    try:
        assert car._key_path() == bound
    finally:
        reset_tenant(tok)


def test_key_path_override_still_wins(tmp_path, monkeypatch):
    # The test-suite convention (and an operator escape hatch): a pinned
    # module attribute takes precedence over tenant resolution.
    pinned = tmp_path / "pinned" / "at_rest.key"
    monkeypatch.setattr(car, "_KEY_PATH", pinned)
    assert car._key_path() == pinned
    assert car._keyring_dir() == pinned.parent / "at_rest.d"


def test_an_unreadable_value_is_logged_once_not_on_every_read(caplog):
    from maverick import world_model

    world_model._WITHHELD_LOGGED.clear()
    with caplog.at_level("DEBUG", logger="maverick.world_model"):
        for _ in range(5):
            world_model._log_withheld_once(car.EncryptionUnavailable("no at-rest key for key-id 00"))
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1 and "repeats of this cause" in errors[0].getMessage()
    assert sum(r.levelname == "DEBUG" for r in caplog.records) == 4
