"""Offline contracts for the administrator's Entra registration tool."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy/azure/register_entra.py"


@pytest.fixture
def registration():
    spec = importlib.util.spec_from_file_location("register_entra", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_origin_must_be_https_and_contain_no_path_or_credentials(registration):
    assert registration.public_origin("https://SECOND.example/") == "https://second.example"
    for value in ("http://second.example", "https://second.example/login", "https://a@second.example", "https://a/?token=x"):
        with pytest.raises(ValueError):
            registration.public_origin(value)


def test_plan_preserves_role_ids_and_other_redirects_on_rerun(registration):
    app = {"appId": "a", "signInAudience": "AzureADMyOrg", "web": {"redirectUris": ["https://existing.example/"]}}
    patch = registration.app_changes(app, "https://second.example", "api://second.example/a", {})
    update = {**app, **patch}
    assert registration.app_changes(update, "https://second.example", "api://second.example/a", {}) == {}
    assert len(update["appRoles"]) == 7
    assert "https://existing.example/" in update["web"]["redirectUris"]
    assert registration.TEAMS_REDIRECT in update["web"]["redirectUris"]
    assert update["api"]["requestedAccessTokenVersion"] == 2
    scope = update["api"]["oauth2PermissionScopes"][0]
    assert scope["value"] == "SecondShift.Copilot.Read"
    assert update["api"]["preAuthorizedApplications"] == [
        {"appId": registration.TOKEN_STORE, "delegatedPermissionIds": [scope["id"]]}
    ]


def test_only_requested_graph_access_is_added(registration):
    existing = [{"resourceAppId": "other", "resourceAccess": [{"id": "old", "type": "Scope"}]}]
    app = {"appId": "a", "signInAudience": "AzureADMyOrg", "requiredResourceAccess": existing}
    patch = registration.app_changes(app, "https://second.example", None, {"Application.Read.All": "requested-id"})
    assert patch["requiredResourceAccess"] == [
        *existing, {"resourceAppId": registration.GRAPH_ID, "resourceAccess": [{"id": "requested-id", "type": "Role"}]}
    ]
    assert "api" not in patch


def test_failed_vault_write_removes_new_password_without_exposing_it(registration, monkeypatch):
    app = {"appId": "a", "id": "object-id"}
    expected = b"test-secret-material"
    calls = []

    def az(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("keyvault", "secret", "list"):
            return []
        assert kwargs.get("stdin") == expected
        assert all(expected.decode() not in arg for arg in args)
        raise ValueError("vault write failed")

    def graph(method, endpoint, body):
        calls.append((method, endpoint, body))
        if endpoint.endswith("/addPassword"):
            return {"secretText": expected.decode(), "keyId": "new-key"}

    monkeypatch.setattr(registration, "az", az)
    monkeypatch.setattr(registration, "graph", graph)
    with pytest.raises(ValueError, match="vault write failed"):
        registration.ensure_password(app, "vault")
    assert calls[-1] == ("POST", "applications/object-id/removePassword", {"keyId": "new-key"})


def test_existing_vault_version_prevents_new_password(registration, monkeypatch):
    monkeypatch.setattr(registration, "password_metadata", lambda vault: [
        {"attributes": {"enabled": True}, "tags": {"entra-app-id": "a"}}
    ])
    monkeypatch.setattr(registration, "graph", lambda *args: pytest.fail("must reuse the existing credential"))
    registration.ensure_password({"appId": "a", "id": "object-id"}, "vault")
    with pytest.raises(ValueError, match="different or unverified"):
        registration.ensure_password({"appId": "b", "id": "other-id"}, "vault")
