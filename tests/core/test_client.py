"""Client binding — one Second Shift deployment, exactly one enterprise client.
The configured client id is the tenant FLOOR, so every data path re-homes under
tenants/<client>/ and a client-bound surface refuses to serve unbound."""
from __future__ import annotations

import pytest

from maverick import client


@pytest.fixture(autouse=True)
def _reset_cache():
    client.reset_client_cache()
    yield
    client.reset_client_cache()


def test_client_id_from_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme-corp")
    assert client.client_id() == "acme-corp"


def test_client_id_invalid_rejected(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "bad id/with slash")
    assert client.client_id() is None


def test_strict_client_id_rejects_invalid_binding(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "Acme")
    with pytest.raises(client.ClientBindingError, match="invalid"):
        client.strict_client_id()


def test_strict_client_id_allows_explicit_unbound_legacy_mode(monkeypatch):
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setattr(client, "_raw_client_id", lambda: "")
    assert client.strict_client_id() is None


def test_corrupt_client_binding_cannot_resolve_shared_storage(monkeypatch):
    from maverick.paths import data_dir

    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(
        client,
        "_raw_client_id",
        lambda: (_ for _ in ()).throw(client.ClientBindingError("corrupt binding")),
    )
    with pytest.raises(client.ClientBindingError, match="corrupt binding"):
        data_dir("world.db")


def test_client_id_none_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setattr(client, "_resolve", lambda: None)
    client.reset_client_cache()
    assert client.client_id() is None


def test_client_id_is_cached(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    assert client.client_id() == "acme"
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "other")  # cache holds the first
    assert client.client_id() == "acme"
    client.reset_client_cache()
    assert client.client_id() == "other"


def test_enforced_via_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ENFORCE", "1")
    assert client.client_binding_enforced() is True


def test_uppercase_client_id_resolves_to_none(monkeypatch):
    # Hot path stays resilient: an invalid (uppercase) id doesn't crash callers.
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "Acme")
    client.reset_client_cache()
    assert client.client_id() is None


def test_client_id_is_the_tenant_floor(monkeypatch):
    from maverick import paths
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    client.reset_client_cache()
    assert paths.current_tenant_id() == "acme"


def test_data_paths_rehome_under_client(monkeypatch, tmp_path):
    from maverick import paths
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    client.reset_client_cache()
    p = paths.data_dir("world.db")
    assert "tenants/acme" in str(p).replace("\\", "/")
    assert p == tmp_path / "tenants" / "acme" / "world.db"


def test_explicit_tenant_scope_overrides_client(monkeypatch):
    from maverick import paths
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    client.reset_client_cache()
    token = paths.set_tenant("explicit")
    try:
        assert paths.current_tenant_id() == "explicit"
    finally:
        paths.reset_tenant(token)


def test_unbound_keeps_legacy_root(monkeypatch):
    from maverick import paths
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "_resolve", lambda: None)
    client.reset_client_cache()
    assert paths.current_tenant_id() is None  # legacy shared root, unchanged
