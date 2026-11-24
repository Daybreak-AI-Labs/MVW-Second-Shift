"""Where Second Shift keeps its named records: the data folder or Postgres.

Many parts of Second Shift keep a small record of their own (enrolled agents,
the trust registry, drift findings, platform checks, waiting Teams cards,
reminders sent, queued ServiceNow incidents, sign-in roles and so on). Each one
used to be a file in the data folder, read whole, changed under a lock and
written back whole. This module keeps that exact shape and decides where the
record lives:

* when the main database is Postgres (``[world_model] backend = "postgres"`` or
  ``SECOND_SHIFT_WORLD_BACKEND=postgres``), every record is one row of the
  ``second_shift_records`` table in that database, keyed by its path relative
  to the data folder. Changing a record holds that row locked
  (``SELECT ... FOR UPDATE``) for the whole change, so two processes or two
  servers never interleave, and a change that fails part way is rolled back;
* otherwise the record stays the file it always was, read and written exactly
  as before.

A module uses :func:`at` with the path it already computes and calls
:meth:`RecordDocument.read_text`, :meth:`~RecordDocument.write_text`,
:meth:`~RecordDocument.exists` and :meth:`~RecordDocument.locked` where it used
to touch the file. Parsing and checking the contents stays in the module.

What this module does not do: decide what a record contains, keep history,
encrypt (the database's own encryption at rest applies), or move records that
are not text (the audit log, signing keys and the SQLite stores keep their own
storage). A record that cannot be read or written raises
:class:`RecordDocumentError`, an ``OSError``, so callers that already refuse on
an unreadable file refuse in the same way. Nothing here falls back to the data
folder when Postgres is configured but unavailable.
"""
from __future__ import annotations

import contextlib
import contextvars
import logging
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

log = logging.getLogger("maverick.record_documents")

TABLE = "second_shift_records"
_SCHEMA_LOCK = 0x5353524543  # "SSREC": serialises creating the table
_MAX_KEY = 512

_HELD: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "second_shift_record_locks", default=None)
_STORES: dict[str, Any] = {}
_STORES_LOCK = threading.Lock()
_SCHEMA_READY: set[str] = set()


class RecordDocumentError(OSError):
    """A record could not be read or written. The message never carries the
    database address or the record's contents."""


def using_postgres() -> bool:
    """True when the main database is Postgres, so records live there too."""
    from .world_model_backends import is_postgres_configured

    return is_postgres_configured()


def at(path: str | Path) -> RecordDocument:
    """The record kept at ``path`` (a path in the data folder)."""
    return RecordDocument(Path(path))


class RecordDocument:
    """One named record. Cheap to make; holds no connection or open file."""

    __slots__ = ("path",)

    def __init__(self, path: Path) -> None:
        self.path = path

    # ----------------------------------------------------------------- reads

    def read_text(self) -> str | None:
        """The record's text, or ``None`` when there is no record yet."""
        if not using_postgres():
            from .file_lock import atomic_read_text

            try:
                return atomic_read_text(self.path)
            except FileNotFoundError:
                return None
        key = _key(self.path)
        held = (_HELD.get() or {}).get(key)
        if held is not None:
            return _select(held, key)
        with _transaction() as cursor:
            return _select(cursor, key)

    def exists(self) -> bool:
        if not using_postgres():
            return self.path.exists()
        return self.read_text() is not None

    # ---------------------------------------------------------------- writes

    def write_text(self, text: str, *, mode: int = 0o600) -> None:
        """Replace the record's text. Inside :meth:`locked` the change commits
        when the lock is let go; a failure before then undoes it."""
        if not isinstance(text, str):
            raise TypeError("a record is text")
        if not using_postgres():
            from .file_lock import atomic_write_text, ensure_private_directory

            ensure_private_directory(self.path.parent)
            atomic_write_text(self.path, text, mode=mode)
            return
        key = _key(self.path)
        held = (_HELD.get() or {}).get(key)
        if held is not None:
            _run(held, f"UPDATE {TABLE} SET body = %s, revision = revision + 1, "
                       "updated_at = now() WHERE key = %s", (text, key))
            return
        with _transaction() as cursor:
            _run(cursor, f"INSERT INTO {TABLE} (key, body) VALUES (%s, %s) "
                         "ON CONFLICT (key) DO UPDATE SET body = EXCLUDED.body, "
                         f"revision = {TABLE}.revision + 1, updated_at = now()", (key, text))

    @contextlib.contextmanager
    def locked(self, *, strict: bool = False) -> Iterator[None]:
        """Hold the record for a read-change-write. With files this is the
        same lock as before; with Postgres it is the record's row, held until
        the block ends. Holding a record already held in this context is
        allowed and changes nothing."""
        if not using_postgres():
            from .file_lock import cross_process_lock, ensure_private_directory

            ensure_private_directory(self.path.parent)
            with cross_process_lock(self.path, strict=strict):
                yield
            return
        key = _key(self.path)
        held = dict(_HELD.get() or {})
        if key in held:
            yield
            return
        with _transaction() as cursor:
            _run(cursor, f"INSERT INTO {TABLE} (key, body) VALUES (%s, NULL) "
                         "ON CONFLICT (key) DO NOTHING", (key,))
            _run(cursor, f"SELECT 1 FROM {TABLE} WHERE key = %s FOR UPDATE", (key,))
            held[key] = cursor
            token = _HELD.set(held)
            try:
                yield
            finally:
                _HELD.reset(token)


# -------------------------------------------------------------- Postgres

def _key(path: Path) -> str:
    """The record's name in the table: its path relative to the data folder,
    with forward slashes, so a tenant's records stay apart as their files do."""
    from .paths import maverick_home

    home = maverick_home().resolve()
    try:
        relative = path.resolve().relative_to(home)
    except ValueError:
        raise RecordDocumentError("a record must be kept in the data folder") from None
    key = relative.as_posix()
    if not key or key == "." or len(key) > _MAX_KEY:
        raise RecordDocumentError("a record must be kept in the data folder")
    return key


def _dsn() -> str:
    from .world_model_backends.postgres import _configured_dsn

    dsn = (os.environ.get("MAVERICK_PG_DSN") or _configured_dsn() or "").strip()
    if not dsn:
        raise RecordDocumentError(
            "The database is set to Postgres but no database address is configured.")
    return dsn


def _store(dsn: str):
    from .postgres_transactions import PostgresTransactions
    from .world_model_backends.postgres import _pool_size

    with _STORES_LOCK:
        store = _STORES.get(dsn)
        if store is None:
            store = PostgresTransactions(dsn, pool_size=_pool_size())
            _STORES[dsn] = store
        return store


@contextlib.contextmanager
def _transaction() -> Iterator[Any]:
    dsn = _dsn()
    store = _store(dsn)
    try:
        if dsn not in _SCHEMA_READY:
            # Its own short transaction: the table is visible to everyone at
            # once, and the setup lock is never held across a record's change.
            with store.transaction() as cursor:
                _ensure_table(cursor)
            _SCHEMA_READY.add(dsn)
        with store.transaction() as cursor:
            yield cursor
    except RecordDocumentError:
        raise
    except Exception as exc:
        if _is_database_error(exc):
            log.warning("saved record unavailable (%s)", type(exc).__name__)
            raise RecordDocumentError("A saved record could not be read from or written to the database.") from None
        raise


def _ensure_table(cursor) -> None:
    cursor.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK,))
    cursor.execute(
        f"CREATE TABLE IF NOT EXISTS {TABLE} ("
        "key text PRIMARY KEY, "
        "body text, "
        "revision bigint NOT NULL DEFAULT 0, "
        "updated_at timestamptz NOT NULL DEFAULT now())")


def _is_database_error(exc: BaseException) -> bool:
    try:
        import psycopg
    except ImportError:  # pragma: no cover -- Postgres needs the [postgres] extra
        return False
    from .postgres_transactions import TransactionAborted

    return isinstance(exc, (psycopg.Error, TransactionAborted)) or (
        isinstance(exc, RuntimeError) and "admission is closed" in str(exc))


def _run(cursor, statement: str, params: tuple) -> None:
    try:
        cursor.execute(statement, params)
    except Exception as exc:
        if _is_database_error(exc):
            log.warning("saved record unavailable (%s)", type(exc).__name__)
            raise RecordDocumentError("A saved record could not be read from or written to the database.") from None
        raise


def _select(cursor, key: str) -> str | None:
    _run(cursor, f"SELECT body FROM {TABLE} WHERE key = %s", (key,))
    row = cursor.fetchone()
    return None if row is None else row[0]


def _reset_for_tests() -> None:
    with _STORES_LOCK:
        _STORES.clear()
    _SCHEMA_READY.clear()


__all__ = ["RecordDocument", "RecordDocumentError", "TABLE", "at", "using_postgres"]
