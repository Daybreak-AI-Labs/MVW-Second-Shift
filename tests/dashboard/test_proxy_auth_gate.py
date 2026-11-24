"""Reverse-proxy SSO wiring in the dashboard's ``require_principal``.

Hermetic: we monkeypatch the ``maverick.proxy_auth`` seams bound into
``maverick_dashboard.auth`` and drive ``require_principal`` with a fake request,
so the tests exercise the dependency wiring (trusted-peer gate -> principal),
not config/IO.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.datastructures import Headers

import maverick_dashboard.auth as auth


def _req(headers=None, host="127.0.0.1", path="/metrics"):
    return SimpleNamespace(
        headers=Headers(headers or {}),
        cookies={},
        url=SimpleNamespace(path=path),
        client=SimpleNamespace(host=host),
        state=SimpleNamespace(),
    )


def test_unreadable_dashboard_auth_policy_cannot_enable_local_admin(monkeypatch):
    from maverick_dashboard import invites, saml

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "0")
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setattr(
        "maverick.config.config_source_errors",
        lambda: {"config.toml": "unreadable"},
    )
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(invites, "invites_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: False)

    assert auth._dashboard_require_auth_enabled() is True
    assert auth.auth_genuinely_off() is False
    with pytest.raises(auth.HTTPException) as exc:
        auth.has_permission(_req(), "admin")
    assert exc.value.status_code == 401


def test_empty_saml_table_is_not_mistaken_for_an_identity_policy(monkeypatch):
    from maverick_dashboard import invites, saml

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"auth": {"saml": {}}},
    )
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(invites, "invites_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: False)

    assert auth._saml_policy_configured() is False
    assert auth.auth_genuinely_off() is True
