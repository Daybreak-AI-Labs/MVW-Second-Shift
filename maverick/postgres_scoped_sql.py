"""Shared PostgreSQL transactions for the browser and recorder relational stores.

The stores share their SQL with SQLite except for bind parameters, schema types
and transaction admission. Each store supplies its own table names and row
policies. Legacy import copies only the current store's reviewed columns.
"""
from __future__ import annotations

import contextlib
import hashlib
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

from .record_documents import _dsn, _is_database_error, _store

_SCOPE = "maverick.local_store_scope"
_LOOKUP = "maverick.local_store_lookup"
_MIGRATIONS = "second_shift_local_store_imports"


class ScopedStoreError(OSError):
    """PostgreSQL or the legacy records could not be used."""


class _Row(dict):
    """Support the numeric and named access the shared queries use."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


def _rows(cursor):
    names = tuple(column.name for column in cursor.description or ())
    return lambda values: _Row(zip(names, values, strict=True))


def workspace_key(workspace: str | None) -> str:
    """Distinguish an unbound installation from every named workspace."""
    return "0" if workspace is None else f"1:{workspace}"


def workspace_setting() -> str:
    return f"nullif(current_setting('{_SCOPE}', true), '')"


def workspace_policy(column: str) -> str:
    return f"{column} = {workspace_setting()}"


def key_policy(column: str) -> str:
    return f"{column} = nullif(current_setting('{_LOOKUP}', true), '')"


def bind(cursor, scope: str, lookup: str = "") -> None:
    cursor.execute("SELECT set_config(%s, %s, true), set_config(%s, %s, true)",
                   (_SCOPE, scope, _LOOKUP, lookup))


def _lock(cursor, part: str) -> None:
    digest = hashlib.sha256(f"second-shift-local-store:{part}".encode()).digest()[:8]
    cursor.execute("SELECT pg_advisory_xact_lock(%s)", (int.from_bytes(digest, "big", signed=True),))


class _Queries:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, statement, params=()):
        return self.cursor.execute(statement.replace("?", "%s"), params)

    def executemany(self, statement, rows):
        return self.cursor.executemany(statement.replace("?", "%s"), rows)


class ScopedStore:
    """Bootstrap forced policies once, then bind each lease to one authority."""

    def __init__(self, name: str, schema: str, policies: Mapping[str, str], *,
                 lookup_policies: Mapping[str, str] | None = None):
        self.name = name
        self.schema = schema.replace(" BLOB", " BYTEA").replace(" REAL", " DOUBLE PRECISION")
        self.policies = policies
        self.lookup_policies = lookup_policies or {}
        self._created: set[str] = set()
        self._imported: set[tuple[str, str]] = set()
        self._setup_lock = threading.Lock()

    def _ensure_schema(self, transactions, dsn: str) -> None:
        if dsn in self._created:
            return
        with self._setup_lock:
            if dsn in self._created:
                return
            with transactions.transaction() as cursor:
                _lock(cursor, "schema")
                cursor.execute(f"CREATE TABLE IF NOT EXISTS {_MIGRATIONS} (name text PRIMARY KEY)")
                cursor.execute(self.schema, prepare=False)
                for table, rule in self.policies.items():
                    cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
                    cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
                    cursor.execute(f"DROP POLICY IF EXISTS second_shift_scope ON {table}")
                    cursor.execute(f"CREATE POLICY second_shift_scope ON {table} USING ({rule}) WITH CHECK ({rule})")
                    if lookup := self.lookup_policies.get(table):
                        cursor.execute(f"DROP POLICY IF EXISTS second_shift_lookup ON {table}")
                        cursor.execute(f"CREATE POLICY second_shift_lookup ON {table} FOR SELECT USING ({lookup})")
            self._created.add(dsn)

    @contextlib.contextmanager
    def transaction(self, scope: str, *, lookup: str = "", writing: str | None = None,
                    legacy: tuple[Path, str, Callable] | None = None) -> Iterator[_Queries]:
        try:
            dsn = _dsn()
            transactions = _store(dsn)
            self._ensure_schema(transactions, dsn)
            if legacy:
                path, partition, import_records = legacy
                self._import(transactions, dsn, path, partition, import_records)
            with transactions.transaction() as cursor:
                bind(cursor, scope, lookup)
                if writing is not None:
                    _lock(cursor, f"{self.name}:{writing}")
                cursor.row_factory = _rows
                yield _Queries(cursor)
        except Exception as exc:
            if _is_database_error(exc):
                raise ScopedStoreError("The saved record could not be read or updated in PostgreSQL.") from None
            raise

    def _import(self, transactions, dsn, path, partition, import_records) -> None:
        # The marker belongs to the logical store, so moving the data directory
        # cannot reimport records a person already erased in PostgreSQL.
        marker = f"{self.name}:{partition}"
        cache_key = (dsn, marker)
        if cache_key in self._imported:
            return
        # The deployment lease excludes a legacy writer during the upgrade.
        # Probe the marker before trying to read an already imported file.
        with self._setup_lock:
            if cache_key in self._imported:
                return
            with transactions.transaction() as cursor:
                _lock(cursor, f"import:{marker}")
                cursor.execute(f"SELECT 1 FROM {_MIGRATIONS} WHERE name = %s", (marker,))
                if not cursor.fetchone():
                    with _legacy_database(path) as previous:
                        if previous is not None:
                            import_records(previous, cursor)
                    cursor.execute(f"INSERT INTO {_MIGRATIONS} (name) VALUES (%s)", (marker,))
            if len(self._imported) >= 8192:
                self._imported.clear()
            self._imported.add(cache_key)


@contextlib.contextmanager
def _legacy_database(path: Path) -> Iterator[sqlite3.Connection | None]:
    from .file_lock import ensure_private_file

    try:
        path.lstat()
    except FileNotFoundError:
        yield None
        return
    try:
        ensure_private_file(path, 0o600)
        connection = sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            yield connection
        finally:
            connection.close()
    except (OSError, sqlite3.Error) as exc:
        raise ScopedStoreError("The previous SQLite record could not be imported. Restore it and retry.") from exc


def copy_legacy(previous, cursor, table: str, columns: str, *,
                where: str = "", params: tuple = (), prefix: tuple = ()) -> None:
    """Copy batches under the same migration transaction and row policies."""
    source_rows = previous.execute(f"SELECT {columns} FROM {table}" + (f" WHERE {where}" if where else ""), params)
    target = ("workspace," if prefix else "") + columns
    placeholders = ",".join(["%s"] * len(target.split(",")))
    statement = f"INSERT INTO {table} ({target}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
    while rows := source_rows.fetchmany(500):
        cursor.executemany(statement, (prefix + row for row in rows))
