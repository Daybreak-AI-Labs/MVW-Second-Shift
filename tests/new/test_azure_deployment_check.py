"""Offline contracts for the Azure deployment smoke check."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy/azure/check_deployment.py"


@pytest.fixture
def deployment_check():
    spec = importlib.util.spec_from_file_location("check_deployment", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_login_redirect_must_name_the_expected_tenant_and_origin(deployment_check):
    tenant = "87a5e803-e91f-4268-ae55-42077ff3e839"
    host = "https://secondshift.example.com"
    location = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?redirect_uri={host}/auth/callback"
    assert deployment_check.entra_redirect(location, host, tenant)
    assert not deployment_check.entra_redirect(location.replace(tenant, "common"), host, None)
    assert not deployment_check.entra_redirect(location.replace("login.microsoftonline.com", "login.example.com"), host, tenant)
    assert not deployment_check.entra_redirect(location, "https://alternate.example.com", tenant)


def test_missing_key_probe_sends_only_headers(deployment_check, monkeypatch):
    from io import BytesIO

    requests = []

    class Connection:
        def __init__(self, *args, **kwargs):
            self.sock = self

        def send(self, data):
            requests.append(data)

        def makefile(self, mode):
            return BytesIO(b"HTTP/1.1 401 Unauthorized\r\n")

        def close(self):
            pass

    monkeypatch.setattr(deployment_check.http.client, "HTTPSConnection", Connection)
    assert deployment_check.rejects_before_body("https://secondshift.example.com")
    assert requests[0].endswith(b"\r\n\r\n")
    assert b"Expect: 100-continue\r\n" in requests[0]
    assert b"Content-Length: 2\r\n" in requests[0]
    assert b"Authorization:" not in requests[0]


def test_admin_check_cleans_up_after_failed_mint_without_printing_secrets(deployment_check, capsys):
    calls = []

    def request(method, path, body=None, auth=None):
        calls.append((method, path, auth))
        if method == "DELETE":
            return 204, {}, {}
        if path.endswith("/credentials"):
            return 409, {}, {"detail": "mint requires approval with a private challenge"}
        return 201, {}, {}

    assert not deployment_check.check_agent(request, {"Authorization": "Bearer test-admin-secret"})
    assert calls[-1][0] == "DELETE"
    assert calls[0][1] + "/" in calls[-1][1]
    out = capsys.readouterr().out
    assert "test-admin-secret" not in out
    assert "private challenge" not in out
    assert "Pass — temporary agent removed" in out


def test_admin_check_uses_returned_key_for_screening_and_rejects_one_wrong_key(deployment_check, capsys):
    seen = []

    def request(method, path, body=None, auth=None):
        if path.endswith("/credentials"):
            return 200, {}, {"token": "ss-rest-test-generated-secret"}
        if path.endswith("/screen"):
            seen.append(auth["Authorization"])
            return (200, {}, {"allowed": True}) if len(seen) == 1 else (401, {}, {})
        return (204 if method == "DELETE" else 201), {}, {}

    assert deployment_check.check_agent(request, {"Authorization": "Bearer test-admin-secret"})
    assert seen[0] == "Bearer ss-rest-test-generated-secret"
    assert seen[0] != seen[1]
    assert "generated-secret" not in capsys.readouterr().out


def test_temporary_agent_flow_works_with_real_dashboard_routes(deployment_check, tmp_path, monkeypatch, capsys):
    from fastapi.testclient import TestClient

    from maverick import world_model
    from maverick_dashboard import auth
    from maverick_dashboard.app import app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        screens = []

        def request(method, path, body=None, auth=None):
            response = client.request(method, path, json=body, headers=auth)
            data = response.json() if response.content else {}
            if path == deployment_check.SCREEN:
                screens.append((response.status_code, data))
            return response.status_code, {}, data

        assert deployment_check.check_agent(request, {}), screens
        assert client.get(deployment_check.ADMIN_AGENTS).json()["agents"] == []
    assert "ss-rest-" not in capsys.readouterr().out
