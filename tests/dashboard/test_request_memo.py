"""Per-request memo for configuration-derived authorization predicates."""
from __future__ import annotations

from fastapi import HTTPException, Request

from maverick_dashboard import auth


def test_anonymous_access_is_rechecked_at_every_gate(monkeypatch):
    # Principal-less access is never remembered: each gate rechecks current
    # local policy, so a policy change takes effect inside the same request.
    import pytest

    checks = {"n": 0}
    allowed = {"v": True}

    def _allowed():
        checks["n"] += 1
        return allowed["v"]

    monkeypatch.setattr(auth, "anonymous_local_access_allowed", _allowed)
    monkeypatch.setattr(auth, "_dashboard_token_authenticated", lambda request: False)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    request = Request(scope)
    assert auth._authorization_principal(request) is None
    assert auth._authorization_principal(Request(scope)) is None  # same scope, same state
    assert checks["n"] == 2

    allowed["v"] = False
    denied = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    with pytest.raises(HTTPException):
        auth._authorization_principal(denied)
    with pytest.raises(HTTPException):
        auth._authorization_principal(denied)
    assert checks["n"] == 4


def test_each_gate_reads_the_configuration_once_and_sees_a_policy_saved_before_it(tmp_path, monkeypatch):
    # A gate's sign-in decision asked about 15 questions of the configuration,
    # each reading and decrypting it again (about 350 reads per page).
    import os

    import pytest

    from maverick import config, crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_ENCRYPTION_KEY", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    with crypto_at_rest.deployment_key_scope():
        token = crypto_at_rest.seal_to_str("sk-test-not-a-real-key")  # pragma: allowlist secret
    config.dashboard_overrides_path().write_text(f'[providers.anthropic]\napi_key = "{token}"\n', encoding="utf-8")
    reads = []
    real = config._read_global_config
    monkeypatch.setattr(config, "_read_global_config", lambda: reads.append(1) or real())
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    try:
        assert auth._authorization_principal(Request(scope)) is None
        assert auth._authorization_principal(Request(scope)) is None
        assert len(reads) == 2
        replacement = tmp_path / "config.toml.new"
        replacement.write_text("[dashboard]\nrequire_auth = true\n", encoding="utf-8")
        os.replace(replacement, tmp_path / "config.toml")
        with pytest.raises(HTTPException):
            auth._authorization_principal(Request(scope))
        assert len(reads) == 3
    finally:
        config.reset_config_cache()


def test_a_gate_inside_a_page_render_reads_a_policy_saved_during_the_render(tmp_path, monkeypatch):
    # A page render reads the configuration once for its display; the
    # navigation's permission checks are gates and read the current files.
    import os

    import pytest

    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    try:
        with config.single_read():  # what templates.TemplateResponse opens
            assert config.load_config()["budget"]["max_dollars"] == 5.0  # the render's read
            assert auth._authorization_principal(Request(scope)) is None
            replacement = tmp_path / "config.toml.new"
            replacement.write_text("[dashboard]\nrequire_auth = true\n", encoding="utf-8")
            os.replace(replacement, tmp_path / "config.toml")
            assert "dashboard" not in config.load_config(), "the render keeps its own read"
            with pytest.raises(HTTPException):
                auth._authorization_principal(Request(scope))
            with pytest.raises(HTTPException):
                auth.has_permission(Request(scope), "view")  # what the navigation asks
    finally:
        config.reset_config_cache()


def test_a_signed_in_role_check_inside_a_render_reads_a_role_saved_during_it(tmp_path, monkeypatch):
    import os

    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text('[test_roles]\nx = "admin"\n', encoding="utf-8")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:x")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: config.load_config()["test_roles"]["x"])
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: config.load_config()["test_roles"]["x"])
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    try:
        with config.single_read():  # what templates.TemplateResponse opens
            assert config.load_config()["test_roles"]["x"] == "admin"  # the render's read
            assert auth.has_permission(Request(scope), "admin") is True
            replacement = tmp_path / "config.toml.new"
            replacement.write_text('[test_roles]\nx = "viewer"\n', encoding="utf-8")
            os.replace(replacement, tmp_path / "config.toml")
            assert auth.has_permission(Request(scope), "admin") is False
            assert auth.has_global_permission(Request(scope), "admin") is False
            assert auth.caller_role(Request(scope)) == "viewer"
    finally:
        config.reset_config_cache()
