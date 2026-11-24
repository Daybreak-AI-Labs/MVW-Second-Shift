"""Fail-closed Ekko control and dashboard authorization tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(tmp_path, monkeypatch, text: str = ""):
    cfg = tmp_path / "config.toml"
    cfg.write_text(text, encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.config import reset_config_cache

    reset_config_cache()
    return cfg


def test_ekko_mutation_requires_same_origin(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    no_origin = TestClient(app, base_url="http://127.0.0.1")
    response = no_origin.post(
        "/api/v1/ekko/candidates/mine",
        json={"device_id": "desk"},
    )
    assert response.status_code == 403


def test_observation_start_fails_closed_when_tenant_audit_is_unavailable(
    tmp_path, monkeypatch,
):
    _isolate(
        tmp_path,
        monkeypatch,
        "\n".join([
            "[ekko]",
            "enable = true",
            'allowed_apps = ["excel", "powerpoint"]',
            "min_occurrences = 2",
            "min_distinct_days = 2",
            "",
        ]),
    )
    from maverick.config import get_ekko_policy
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    store = WorkDiscoveryStore(local_os_principal(), "desk")
    store.enroll(get_ekko_policy())
    monkeypatch.setattr("maverick.audit.record", lambda *_a, **_k: False)

    response = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": True},
    )

    assert response.status_code == 503
    assert store.list_sessions() == []
