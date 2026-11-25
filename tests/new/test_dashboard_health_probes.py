"""Readiness checks the database scope used by dashboard traffic."""

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    ("rls", "tenant", "bypasses", "read_only", "expected"),
    [(True, None, False, False, 503), (True, "test-workspace", True, False, 503),
     (True, "test-workspace", False, False, 200), (False, None, True, False, 200),
     (True, "test-workspace", False, True, 503), (False, None, True, True, 503)],
)
def test_postgres_readiness_requires_a_usable_workspace(monkeypatch, rls, tenant, bypasses, read_only, expected):
    import importlib

    from maverick.world_model_backends import postgres

    dashboard = importlib.import_module("maverick_dashboard.app")
    world = postgres.PostgresWorldModel.__new__(postgres.PostgresWorldModel)
    world._rls = rls

    @contextmanager
    def transaction():
        queries = []

        def result():
            query = queries[-1]
            return (not ((read_only and "transaction_read_only" in query)
                         or (bypasses and "rolbypassrls" in query)),)

        yield SimpleNamespace(execute=queries.append, fetchone=result)

    monkeypatch.setattr(world, "_tx", transaction)
    monkeypatch.setattr(postgres, "_active_tenant", lambda: tenant)
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    assert client.get("/livez").status_code == 200
    assert client.get("/healthz").status_code == 200
    response = client.get("/readyz")
    assert response.status_code == expected
    assert response.json() == {"status": "ok" if expected == 200 else "degraded"}


def test_postgres_read_only_session_is_not_ready(records_in_postgres, monkeypatch):
    import importlib

    from maverick.world_model_backends.postgres import PostgresWorldModel

    dashboard = importlib.import_module("maverick_dashboard.app")
    monkeypatch.setenv("MAVERICK_PG_POOL_SIZE", "0")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    with PostgresWorldModel(dsn=records_in_postgres) as world:
        monkeypatch.setattr(dashboard, "_world", lambda: world)
        client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
        assert client.get("/readyz").status_code == 200
        with world._tx() as cursor:
            cursor.execute("SET default_transaction_read_only = on")
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 503


@pytest.mark.asyncio
async def test_readiness_times_out_without_starting_duplicate_database_checks(monkeypatch):
    import importlib

    from starlette.responses import JSONResponse

    dashboard = importlib.import_module("maverick_dashboard.app")
    release = asyncio.Event()
    finished = asyncio.Event()
    calls = []

    async def probe(*, require_workspace=False):
        calls.append(require_workspace)
        await release.wait()
        finished.set()
        return JSONResponse({"status": "ok"})

    monkeypatch.setattr(dashboard, "_database_probe", probe)
    monkeypatch.setattr(dashboard, "_READINESS_RESPONSE_SECONDS", 0.01, raising=False)
    async with asyncio.timeout(1):
        responses = await asyncio.gather(dashboard.readyz(), dashboard.readyz())
    assert [response.status_code for response in responses] == [503, 503]
    assert calls == [True]
    release.set()
    await asyncio.wait_for(finished.wait(), timeout=1)
    assert (await dashboard.readyz()).status_code == 200
    assert calls == [True, True]
