"""Multi-tenant isolation tests.

The tenancy story is only as good as its walls. These tests prove, across the
primitives that actually carry tenant data, that one tenant cannot read,
write, or decrypt another's:

  * **path routing** — ``data_dir`` lands each tenant under its own
    ``tenants/<t>/`` subtree (and distinct ids never collide onto one segment);
  * **world model** — ``world_for_tenant`` gives distinct DBs; a goal created
    under tenant A is invisible to tenant B;
  * **per-tenant KMS** — one tenant's DEK cannot open another's data, and a
    DEK wrapped for A does not unwrap under B's context;
  * **scope discipline** — ``set_tenant``/``reset_tenant`` restore cleanly and
    are independent across contexts.

Pure/offline: a temp ``MAVERICK_HOME`` so nothing touches the real home.
"""
from __future__ import annotations

import pytest
from maverick.paths import current_tenant, data_dir, reset_tenant, set_tenant


@pytest.fixture(autouse=True)
def _temp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tok = set_tenant(None)
    yield
    reset_tenant(tok)


def test_data_dir_walls_tenants():
    a = data_dir("world.db", tenant="acme")
    b = data_dir("world.db", tenant="globex")
    assert a != b
    assert "tenants/acme/" in str(a).replace("\\", "/")
    assert "tenants/globex/" in str(b).replace("\\", "/")
    # No tenant -> legacy shared path (no tenants/ segment).
    assert "tenants/" not in str(data_dir("world.db", tenant=None)).replace("\\", "/")


def test_distinct_ids_never_collide_on_segment():
    # Non-aliasing ids retain distinct portable namespaces.
    seen = set()
    for tid in ("acme", "ac/me", "ac me", "acme-1", "acme_1", "a.c.m.e"):
        seg = str(data_dir(tenant=tid))
        assert seg not in seen, f"{tid!r} collided onto an existing segment"
        seen.add(seg)

    # Case aliases and Win32 trailing-dot aliases are rejected rather than
    # being allowed to address the same physical directory.
    from maverick.paths import InvalidTenantError, TenantNamespaceCollision
    with pytest.raises(TenantNamespaceCollision):
        data_dir(tenant="ACME")
    with pytest.raises(InvalidTenantError, match="cannot end"):
        data_dir(tenant="acme.")
    with pytest.raises(InvalidTenantError, match="cannot end"):
        data_dir(tenant="acme ")


def test_active_tenant_scope_restores():
    assert current_tenant() is None
    tok = set_tenant("acme")
    try:
        assert current_tenant() == "acme"
        assert "tenants/acme/" in str(data_dir("x")).replace("\\", "/")
    finally:
        reset_tenant(tok)
    assert current_tenant() is None  # cleanly restored


def test_world_for_tenant_distinct_dbs():
    from maverick import world_model
    world_model._tenant_worlds.clear()
    wa = world_model.world_for_tenant("acme")
    wb = world_model.world_for_tenant("globex")
    assert wa is not wb
    assert wa.path != wb.path

    gid = wa.create_goal("acme secret plan", "do not leak", owner="")
    # Tenant B sees none of A's goals.
    assert wb.get_goal(gid) is None
    assert all(g.title != "acme secret plan" for g in wb.list_goals(limit=100))
    # A still has it.
    assert wa.get_goal(gid) is not None
    world_model._tenant_worlds.clear()


def test_world_for_tenant_caches_same_instance():
    from maverick import world_model
    world_model._tenant_worlds.clear()
    assert world_model.world_for_tenant("acme") is world_model.world_for_tenant("acme")
    world_model._tenant_worlds.clear()


def test_tenant_dek_distinct_and_non_transferable():
    from maverick.tenant.kms import tenant_dek
    dek_a = tenant_dek("acme")
    dek_b = tenant_dek("globex")
    assert dek_a != dek_b
    # Deterministic per tenant (so a restart reopens the same data)...
    assert tenant_dek("acme") == dek_a
    # ...but no overlap between tenants.
    assert len(dek_a) >= 16 and dek_a != dek_b


def test_wrapped_dek_does_not_unwrap_cross_tenant():
    from maverick.crypto_at_rest import EncryptionUnavailable
    from maverick.tenant.kms import LocalKMS, tenant_dek
    kms = LocalKMS()
    dek = tenant_dek("acme")
    wrapped = kms.wrap(dek, context=b"tenant:acme")
    # Same context round-trips.
    assert kms.unwrap(wrapped, context=b"tenant:acme") == dek
    # A different tenant's context must NOT recover the DEK (AEAD AAD binds it):
    # the AESGCM InvalidTag surfaces as EncryptionUnavailable.
    with pytest.raises(EncryptionUnavailable):
        kms.unwrap(wrapped, context=b"tenant:globex")


def test_tenant_world_cache_evicts_lru_not_raises(monkeypatch, tmp_path):
    # Reaching MAX_TENANT_WORLDS evicts the least-recently-used tenant
    # instead of hard-failing the next one. Shrink the cap for the test.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import world_model
    world_model._tenant_worlds.clear()
    monkeypatch.setattr(world_model, "MAX_TENANT_WORLDS", 3)

    w_a = world_model.world_for_tenant("a")
    world_model.world_for_tenant("b")
    world_model.world_for_tenant("c")          # cache full (3)
    # Touch "a" so it is most-recently-used; "b" is now the LRU.
    assert world_model.world_for_tenant("a") is w_a
    world_model.world_for_tenant("d")          # over cap -> evict LRU ("b")

    keys = [key.replace("\\", "/") for key in world_model._tenant_worlds]
    assert len(world_model._tenant_worlds) == 3
    assert not any(k.endswith("b/world.db") for k in keys)   # b evicted
    assert any(k.endswith("a/world.db") for k in keys)       # a kept (recently used)
    assert any(k.endswith("d/world.db") for k in keys)       # d added
    world_model._tenant_worlds.clear()


def test_tenant_world_cache_never_evicts_shared(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import world_model
    world_model._tenant_worlds.clear()
    monkeypatch.setattr(world_model, "MAX_TENANT_WORLDS", 2)

    world_model.world_for_tenant(None)         # the shared world
    world_model.world_for_tenant("t1")
    world_model.world_for_tenant("t2")         # at cap; next evicts a TENANT
    world_model.world_for_tenant("t3")

    from maverick.paths import data_dir
    shared_key = world_model._world_cache_key(data_dir("world.db", tenant=None))
    assert shared_key in world_model._tenant_worlds  # shared never evicted
    world_model._tenant_worlds.clear()
