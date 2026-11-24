"""Data plane: the audit log is tenant-isolated via ``maverick.paths``.

Completes the cross-session-memory increment by routing the audit dir AND the
signing-key dir through the tenant-aware ``data_dir`` helper. With no tenant the
paths stay EXACTLY the legacy ``~/.maverick/audit/...`` (single-tenant
unchanged); with a tenant active each tenant gets its own, self-consistent
Ed25519/Merkle chain under ``~/.maverick/tenants/<t>/audit/...``.

The on-disk format and chain semantics are unchanged -- only *where* the
directory is resolved. These tests reuse the existing ``verify_chain`` API.
"""
from __future__ import annotations
from maverick.audit.writer import AuditLog, default_audit_log
from maverick.paths import reset_tenant, set_tenant


def _reset_default_logs(monkeypatch):
    import maverick.audit.writer as writer

    monkeypatch.setattr(writer, "_default", None)
    monkeypatch.setattr(writer, "_defaults", {})


def test_audit_dir_no_tenant_is_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    log = AuditLog()
    assert log.audit_dir == tmp_path / ".maverick" / "audit"
    assert "tenants" not in log.audit_dir.parts


def test_default_audit_log_no_tenant_is_legacy(monkeypatch, tmp_path):
    # The module singleton also resolves the legacy dir when no tenant is set.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _reset_default_logs(monkeypatch)
    assert default_audit_log().audit_dir == tmp_path / ".maverick" / "audit"


def test_key_dir_no_tenant_is_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit import signing

    assert signing._key_dir() == tmp_path / ".maverick" / "audit" / "keys"


def test_audit_dir_follows_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit import signing

    tok = set_tenant("acme")
    try:
        assert AuditLog().audit_dir == (
            tmp_path / ".maverick" / "tenants" / "acme" / "audit"
        )
        assert signing._key_dir() == (
            tmp_path / ".maverick" / "tenants" / "acme" / "audit" / "keys"
        )
    finally:
        reset_tenant(tok)


def test_default_audit_log_is_cached_per_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _reset_default_logs(monkeypatch)

    acme_dir = tmp_path / ".maverick" / "tenants" / "acme" / "audit"
    globex_dir = tmp_path / ".maverick" / "tenants" / "globex" / "audit"

    tok = set_tenant("acme")
    try:
        acme_log = default_audit_log()
        assert acme_log.audit_dir == acme_dir
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        globex_log = default_audit_log()
        assert globex_log.audit_dir == globex_dir
    finally:
        reset_tenant(tok)

    tok = set_tenant("acme")
    try:
        assert default_audit_log() is acme_log
    finally:
        reset_tenant(tok)
    assert globex_log is not acme_log
