"""Readiness checks the database scope used by dashboard traffic."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    ("rls", "tenant", "bypasses", "expected"),
    [(True, None, False, 503), (True, "test-workspace", True, 503),
     (True, "test-workspace", False, 200), (False, None, True, 200)],
)
def test_postgres_readiness_requires_a_usable_workspace(monkeypatch, rls, tenant, bypasses, expected):
    import importlib

    from maverick.world_model_backends import postgres

    dashboard = importlib.import_module("maverick_dashboard.app")
    world = postgres.PostgresWorldModel.__new__(postgres.PostgresWorldModel)
    world._rls = rls

    @contextmanager
    def transaction():
        queries = []
        yield SimpleNamespace(execute=queries.append,
                              fetchone=lambda: (not bypasses,) if "rolbypassrls" in queries[-1] else (1,))

    monkeypatch.setattr(world, "_tx", transaction)
    monkeypatch.setattr(postgres, "_active_tenant", lambda: tenant)
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    assert client.get("/livez").status_code == 200
    assert client.get("/healthz").status_code == 200
    response = client.get("/readyz")
    assert response.status_code == expected
    assert response.json() == {"status": "ok" if expected == 200 else "degraded"}
