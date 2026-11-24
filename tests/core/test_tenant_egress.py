"""Per-tenant egress policy plane."""
from __future__ import annotations

from maverick.tenant import egress as te


def test_no_policy_allows_all():
    assert te.host_allowed("example.com", policy={}) is True
    assert te.host_allowed("example.com", policy=None, tenant=None) is True


def test_deny_wins():
    pol = {"allow": ["*"], "deny": ["169.254.169.254", "*.evil.test"]}
    assert te.host_allowed("169.254.169.254", policy=pol) is False
    assert te.host_allowed("api.evil.test", policy=pol) is False
    assert te.host_allowed("api.good.test", policy=pol) is True


def test_nonempty_allow_restricts():
    pol = {"allow": ["api.acme.com", "*.acme-internal.net"]}
    assert te.host_allowed("api.acme.com", policy=pol) is True
    assert te.host_allowed("db.acme-internal.net", policy=pol) is True
    assert te.host_allowed("api.other.com", policy=pol) is False


def test_per_tenant_override_beats_default(monkeypatch):
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: {
        "egress": {"deny": ["metadata.internal"]},
        "tenancy": {"egress": {"acme": {"allow": ["api.acme.com"]}}},
    })
    # acme is restricted to its allow-list.
    assert te.host_allowed("api.acme.com", tenant="acme") is True
    assert te.host_allowed("api.other.com", tenant="acme") is False
    # beta has no override -> the default plane (deny metadata, else allow).
    assert te.host_allowed("metadata.internal", tenant="beta") is False
    assert te.host_allowed("anything.com", tenant="beta") is True


def test_active_tenant_lookup_uses_raw_env_tenant_id(monkeypatch):
    import maverick.config as cfg

    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setenv("MAVERICK_TENANT", "slack:U123")
    monkeypatch.setattr(cfg, "load_config", lambda: {
        "tenancy": {"egress": {"slack:U123": {"allow": ["api.allowed.test"]}}},
    })

    assert te.host_allowed("api.allowed.test") is True
    assert te.host_allowed("attacker.example") is False


def test_unreadable_config_denies_instead_of_allowing_all(tmp_path, monkeypatch):
    # A malformed config.toml loads as defaults; the deny list it held must not
    # silently become "unrestricted".
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text('[egress]\ndeny = ["169.254.169.254"]\nthis is not toml\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.load_config()
    assert config.config_source_errors(include_tenant=True)
    assert te.host_allowed("169.254.169.254", tenant=None) is False
    assert te.host_allowed("evil.com", tenant=None) is False
