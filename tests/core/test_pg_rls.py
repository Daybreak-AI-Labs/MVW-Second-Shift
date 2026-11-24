"""Guided opt-in for Postgres RLS: ownership/legacy-row preflight + NULL backfill.

These exercise the pure SQL-orchestration logic against a fake connection (no
live Postgres), the way test_postgres_rls_unit.py tests policy SQL -- so they run
everywhere, including CI without a DSN.
"""
from __future__ import annotations

import pytest

from maverick.world_model_backends import pg_rls
from maverick.world_model_backends.pg_rls import _PREFLIGHT_TABLES


class _FakeCursor:
    def __init__(self, conn: _FakeConn) -> None:
        self.conn = conn
        self._result: tuple | None = None
        self.rowcount = 0

    def execute(self, sql: str, params: tuple | None = None) -> None:
        self.conn.calls.append((sql, params))
        s = sql.strip().lower()
        if s.startswith("select rolsuper or rolbypassrls"):
            self._result = (self.conn.bypass,)
        elif "current_user" in s:
            self._result = (self.conn.role,)
        elif "to_regclass" in s:
            tbl = params[0]
            self._result = (tbl if self.conn.tables.get(tbl, {}).get("exists") else None,)
        elif "pg_get_userbyid" in s:
            info = self.conn.tables[params[0]]
            self._result = (info["owner"], info.get("rls", False), info.get("force", False))
        elif s.startswith("select count(*)"):
            tbl = sql.split("FROM ")[1].split()[0]
            empty = self.conn.tables[tbl].get("empty", 0)
            count = self.conn.tables[tbl]["nulls"] if "is null" in s else 0
            self._result = (count + (empty if "= ''" in s else 0),)
        elif s.startswith("update"):
            tbl = sql.split("UPDATE ")[1].split()[0]
            self.rowcount = self.conn.tables[tbl]["nulls"]
            if "= ''" in s:
                self.rowcount += self.conn.tables[tbl].get("empty", 0)
            self.conn.updated[tbl] = params[0]
        else:  # pragma: no cover - defensive
            self._result = None

    def fetchone(self) -> tuple | None:
        return self._result

    def fetchmany(self, size: int = 0) -> list:
        return []  # the fake store holds no encrypted values to re-seal

    def close(self) -> None:
        pass


class _FakeConn:
    def __init__(self, role: str, tables: dict[str, dict]) -> None:
        self.role = role
        self.bypass = False
        self.tables = tables
        self.calls: list = []
        self.updated: dict[str, str] = {}
        self.committed = False

    def cursor(self, name: str | None = None, **_kwargs) -> _FakeCursor:
        return _FakeCursor(self)

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        pass


def _tables(role="app", *, nulls=0, exists=True, owner=None):
    owner = owner if owner is not None else role
    return {t: {"exists": exists, "owner": owner, "nulls": nulls}
            for t in _PREFLIGHT_TABLES}


def test_preflight_ready_when_owned_and_no_legacy_rows():
    conn = _FakeConn("app", _tables("app", nulls=0))
    rep = pg_rls.preflight(conn)
    assert rep["role"] == "app"
    assert rep["ready"] is True
    assert all(i["owned_by_current_role"] and i["null_tenant_rows"] == 0
               for i in rep["tables"].values())


def test_preflight_not_ready_with_legacy_null_rows():
    conn = _FakeConn("app", _tables("app", nulls=7))
    rep = pg_rls.preflight(conn)
    assert rep["ready"] is False
    assert all(i["null_tenant_rows"] == 7 for i in rep["tables"].values())


def test_preflight_not_ready_when_role_does_not_own_table():
    conn = _FakeConn("app", _tables("app", nulls=0, owner="postgres"))
    rep = pg_rls.preflight(conn)
    assert rep["ready"] is False
    assert all(i["owned_by_current_role"] is False for i in rep["tables"].values())


def test_preflight_flags_missing_table_without_raising():
    conn = _FakeConn("app", _tables("app", exists=False))
    rep = pg_rls.preflight(conn)
    assert rep["ready"] is False
    assert all(i.get("missing") for i in rep["tables"].values())


@pytest.mark.parametrize("table", pg_rls._EMPTY_TENANT_TABLES)
def test_preflight_reports_empty_event_scope_and_requires_ownership(table):
    tables = _tables()
    tables[table]["empty"] = 2
    conn = _FakeConn("app", tables)
    report = pg_rls.preflight(conn)
    assert not report["ready"]
    assert report["tables"][table]["null_tenant_rows"] == 0
    assert report["tables"][table]["empty_tenant_rows"] == 2
    tables[table]["empty"] = 0
    tables[table]["owner"] = "other"
    assert not pg_rls.preflight(conn)["ready"]
