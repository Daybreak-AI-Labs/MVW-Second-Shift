"""Fixtures shared by the tests written for Second Shift."""
from __future__ import annotations

import os
import uuid

import pytest


@pytest.fixture
def records_in_postgres(tmp_path, monkeypatch):
    """Keep this test's records in its own throwaway Postgres database.

    Skips without ``MAVERICK_PG_DSN`` (a Postgres login that may create
    databases). Sets the main database to Postgres, so every record that goes
    through :mod:`maverick.record_documents` lands in the table, and yields the
    database address. The database is dropped afterwards."""
    dsn = os.environ.get("MAVERICK_PG_DSN", "")
    if not dsn:
        pytest.skip("MAVERICK_PG_DSN not set (no Postgres test service)")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    from maverick import config, record_documents

    database = "ss_records_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    isolated = make_conninfo(dsn, dbname=database)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_PG_DSN", isolated)
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.delenv("MAVERICK_PG_POOL_SIZE", raising=False)
    config.reset_config_cache()
    record_documents._reset_for_tests()
    try:
        yield isolated
    finally:
        record_documents._reset_for_tests()
        config.reset_config_cache()
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))


def saved_records(dsn: str) -> dict[str, str | None]:
    """Every record in the table, by key, for assertions."""
    import psycopg

    with psycopg.connect(dsn) as connection:
        rows = connection.execute("SELECT key, body FROM second_shift_records ORDER BY key").fetchall()
    return {key: body for key, body in rows}
