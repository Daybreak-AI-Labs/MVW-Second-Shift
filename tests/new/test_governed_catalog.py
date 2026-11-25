"""Governed-record schema verification reads fresh PostgreSQL catalog data."""
from __future__ import annotations

import os

import pytest

from maverick.governed_records import PostgresGovernedRecordBackend
from tools.load_check import test_database as temporary_postgres


def test_governed_catalog_is_checked_in_one_statement_after_bootstrap():
    dsn = os.environ.get("MAVERICK_PG_DSN")
    if not dsn:
        pytest.skip("No PostgreSQL test service")
    with temporary_postgres(dsn) as (_, _, isolated):
        backend = PostgresGovernedRecordBackend("sample", "sample", dsn=isolated)
        assert backend._schema_status() == "missing"
        backend._ensure_schema()

        statements = []

        class CountingCursor:
            def __init__(self, cursor):
                self.cursor = cursor

            def execute(self, *args):
                statements.append(args)
                return self.cursor.execute(*args)

            def __getattr__(self, name):
                return getattr(self.cursor, name)

        with backend._raw_transaction() as cursor:
            assert backend._schema_status_on(CountingCursor(cursor)) == "ready"
        assert len(statements) == 1

        with backend._raw_transaction() as cursor:
            cursor.execute("ALTER TABLE governed_records NO FORCE ROW LEVEL SECURITY")
        assert backend._schema_status() == "incompatible"
