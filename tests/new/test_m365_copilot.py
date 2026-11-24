"""Read-only Copilot access through a delegated Entra bearer."""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

_TENANT = "6196b0a3-7b86-4380-a5cb-f4cdde5850e6"
_APP = "b19dd014-237b-4712-aa06-a97013e83d72"
_STORE = "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b"
_ORIGIN = "http://127.0.0.1"
_API = "/api/v1/m365-copilot"
_SCOPE = "SecondShift.Copilot.Read"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from maverick import config, external_agents, oidc, world_model
    from maverick_dashboard import auth
    from maverick_dashboard.app import app

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = f"https://login.microsoftonline.com/{_TENANT}/v2.0"
    for name, value in {
        "MAVERICK_HOME": str(tmp_path), "MAVERICK_CONFIG": str(tmp_path / "config.toml"),
        "MAVERICK_OIDC_ENABLED": "1", "MAVERICK_OIDC_ISSUER": issuer, "MAVERICK_OIDC_AUDIENCE": _APP,
        "MAVERICK_EXTERNAL_AGENTS": "1", "MAVERICK_DASHBOARD_TOKEN": "local-fixture-dashboard",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_PROXY_AUTH"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text(
        '[auth.oidc.role_map]\n"SecondShift.Viewer" = "viewer"\n"SecondShift.Approver" = "approver"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token: oidc.verify_oidc_token(token, signing_key=private.public_key()))
    monkeypatch.setattr(external_agents, "roster", lambda: [{
        "id": "sample-agent", "platform": "custom", "platform_label": "Custom",
        "active": True, "lifecycle": "active", "contained": True, "over_budget": True,
        "period_spent": 18.0, "max_dollars": 10.0, "period": "monthly", "external_ref": "foundry:sample",
        "credentials": ["rest"], "description": "Private implementation details",
    }])

    def client(role=None, **claims):
        headers = {"Origin": _ORIGIN}
        if role:
            now = int(time.time())
            payload = {"iss": issuer, "aud": _APP, "tid": _TENANT, "sub": "viewer-subject",
                       "oid": "ce937585-2212-415a-b5e7-bd11de17add1", "ver": "2.0",
                       "scp": _SCOPE, "azp": _STORE, "iat": now - 1, "exp": now + 300,
                       "roles": [f"SecondShift.{role}"], **claims}
            headers["Authorization"] = "Bearer " + jwt.encode(payload, private, algorithm="RS256")
        return TestClient(app, base_url=_ORIGIN, headers=headers, follow_redirects=False)

    yield client
    config.reset_config_cache()


def test_copilot_requires_a_delegated_token_issued_to_the_token_store(setup):
    path = _API + "/attention"
    assert setup().get(path).status_code == 401
    assert setup().get(path, headers={"Authorization": "Bearer local-fixture-dashboard"}).status_code == 401
    assert setup("Viewer", scp="").get(path).status_code == 401
    assert setup("Viewer", azp=_APP).get(path).status_code == 401
    assert setup("Viewer", aud="another-service").get(path).status_code == 401
    assert setup("Viewer").get(path).status_code == 200
    assert setup("Viewer").get("/api/v1/external-agents").status_code == 403
    assert setup("Viewer").post(path).status_code in (403, 405)


def test_attention_and_status_project_the_roster_without_private_fields(setup, monkeypatch):
    from maverick import agent_drift, agent_watch

    monkeypatch.setattr(agent_drift, "detail", lambda _, **kwargs: {"state": "baseline_approved"})
    monkeypatch.setattr(agent_watch, "platform_view", lambda _: {"missing_on_platform": True})
    viewer = setup("Viewer")
    attention = viewer.get(_API + "/attention")
    assert attention.status_code == 200
    assert attention.headers["Cache-Control"] == "private, no-store"
    assert attention.json()["agents"][0]["blocked"] and attention.json()["agents"][0]["over_budget"]
    status = viewer.get(_API + "/agent", params={"name": "Sample-Agent"})
    assert status.json()["agent"]["name"] == "sample-agent"
    assert status.json()["agent"]["missing_on_platform"] is True
    assert "credentials" not in status.text and "Private implementation details" not in attention.text
    assert viewer.get(_API + "/agent", params={"name": "unknown"}).status_code == 404


def test_changes_and_found_agents_use_the_current_authorized_views(setup, monkeypatch):
    from maverick import agent_drift, agent_watch

    def changes(since, *, now):
        assert 0 <= now - since < 7 * 86400
        return [{"agent_id": "sample-agent", "summary": "The approved model changed.",
                 "severity": "high", "reported_at": now, "acknowledged": False}]

    monkeypatch.setattr(agent_drift, "findings_reported_since", changes, raising=False)
    monkeypatch.setattr(agent_watch, "unenrolled", lambda: [
        {"platform": "foundry", "external_ref": "foundry:sample", "name": "Added", "last_seen_at": 1},
        {"platform": "foundry", "external_ref": "foundry:other", "name": "Found agent", "last_seen_at": 2},
    ])
    viewer = setup("Viewer")
    changed = viewer.get(_API + "/changed").json()
    assert changed["changes"][0]["summary"] == "The approved model changed."
    assert [a["name"] for a in viewer.get(_API + "/found").json()["agents"]] == ["Found agent"]


def test_approval_summaries_follow_the_queue_permissions(setup, monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import content_access
    from maverick_dashboard import m365_copilot_api as api

    rows = [SimpleNamespace(id=i, action="Update record", detail="Private action details",
                            scope="Internal", risk="high", requested_at=1000) for i in (1, 2)]
    monkeypatch.setattr(api, "_world", lambda: SimpleNamespace(pending_approvals=lambda: rows))
    monkeypatch.setattr(content_access, "can_read_approval", lambda request, approval, world: approval.id == 1)
    assert setup("Viewer").get(_API + "/approvals").status_code == 403
    approver = setup("Approver").get(_API + "/approvals")
    assert [item["id"] for item in approver.json()["approvals"]] == [1]
    assert "Private action details" not in approver.text


def test_package_references_only_the_runtime_read_operations(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path
    from zipfile import ZipFile

    from maverick_dashboard.m365_copilot_api import router

    script = Path(__file__).resolve().parents[2] / "m365-copilot" / "build.py"
    package = tmp_path / "second-shift.zip"
    subprocess.run([
        sys.executable, str(script), "--origin", "https://second-shift.example.test",
        "--package-id", _APP, "--tenant-id", _TENANT,
        "--application-id-uri", "api://second-shift.example.test/" + _APP,
        "--auth-config-id", "registration-fixture", "--privacy-url", "https://second-shift.example.test/privacy",
        "--terms-url", "https://second-shift.example.test/terms", "--output", str(package),
    ], check=True, capture_output=True)
    with ZipFile(package) as archive:
        assert set(archive.namelist()) == {
            "manifest.json", "declarative-agent.json", "api-plugin.json", "openapi.json", "color.png", "outline.png",
        }
        definition = json.loads(archive.read("openapi.json"))
        plugin = json.loads(archive.read("api-plugin.json"))
        assert definition["servers"] == [{"url": "https://second-shift.example.test"}]
        assert all(set(verbs) == {"get"} for verbs in definition["paths"].values())
        operations = {path: spec["get"]["operationId"] for path, spec in definition["paths"].items()}
        assert operations == {route.path: route.operation_id for route in router.routes}
        runtime = plugin["runtimes"][0]
        assert runtime["auth"] == {"type": "OAuthPluginVault", "reference_id": "registration-fixture"}
        assert set(runtime["run_for_functions"]) == set(operations.values())
