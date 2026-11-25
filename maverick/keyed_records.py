"""Per-key PostgreSQL records that formerly shared one named document.

Stores keep their existing file implementation and switch to this companion to
record_documents on PostgreSQL. A first access validates the old document under
the same transaction that installs the rows. Later requests touch indexed rows.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from . import record_documents as records

TABLE = "second_shift_keyed_records"
_SETS = "second_shift_keyed_sets"
_COUNTS = "second_shift_keyed_counts"
_READY: set[str] = set()
_SCHEMA_LOCK = 0x53534B4559
_SCHEMA = f"""
    CREATE TABLE IF NOT EXISTS {_SETS} (address text PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS {_COUNTS} (
        address text REFERENCES {_SETS}(address) NOT NULL,
        name text NOT NULL, total bigint NOT NULL CHECK (total >= 0),
        PRIMARY KEY (address,name)
    );
    CREATE TABLE IF NOT EXISTS {TABLE} (
        address text REFERENCES {_SETS}(address) NOT NULL,
        name text NOT NULL, key_id bytea NOT NULL, entry_key text NOT NULL,
        body text NOT NULL, tag bytea NOT NULL, stamp double precision NOT NULL,
        PRIMARY KEY (address,name,key_id)
    );
    CREATE INDEX IF NOT EXISTS second_shift_keyed_tag ON {TABLE}(address,name,tag);
    CREATE INDEX IF NOT EXISTS second_shift_keyed_stamp ON {TABLE}(address,name,stamp,key_id);
"""


def _digest(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


class KeyedRecords:
    def __init__(self, path: Path, *, legacy: Iterable[Path] = ()):
        self.path = path
        self.legacy = (path, *legacy)

    def _ensure_schema(self) -> None:
        dsn = records._dsn()
        if dsn in _READY:
            return
        with records._transaction() as cursor:
            records._run(cursor, "SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK,))
            cursor.execute(_SCHEMA, prepare=False)
        _READY.add(dsn)

    @contextmanager
    def transaction(self, migrate: Callable[[Collection], None], *, write: bool = False) -> Iterator[Collection]:
        address = records._key(self.path)
        self._ensure_schema()
        with records._transaction() as cursor:
            collection = Collection(cursor, address)
            stmt = f"SELECT 1 FROM {_SETS} WHERE address = %s"
            records._run(cursor, stmt + (" FOR UPDATE" if write else ""), (address,))
            if cursor.fetchone() is None:
                records._run(cursor, f"INSERT INTO {_SETS}(address) VALUES (%s) ON CONFLICT DO NOTHING RETURNING 1",
                             (address,))
                if cursor.fetchone() is not None:
                    # Reuse the same cursor for old-document reads and ensures
                    # the document and its replacement commit together.
                    old_keys = [records._key(path) for path in self.legacy]
                    held = dict(records._HELD.get() or {})
                    for key in sorted(old_keys):
                        records._run(cursor, f"INSERT INTO {records.TABLE} (key,body) VALUES (%s,NULL) "
                                     "ON CONFLICT DO NOTHING", (key,))
                        records._run(cursor, f"SELECT 1 FROM {records.TABLE} WHERE key = %s FOR UPDATE", (key,))
                        held[key] = cursor
                    token = records._HELD.set(held)
                    try:
                        migrate(collection)
                        for key in old_keys:
                            records._run(cursor, f"UPDATE {records.TABLE} SET body = NULL WHERE key = %s", (key,))
                    finally:
                        records._HELD.reset(token)
                elif write:
                    records._run(cursor, stmt + " FOR UPDATE", (address,))
            yield collection


class Collection:
    def __init__(self, cursor, address: str):
        self.cursor = cursor
        self.address = address

    def rows(self, name: str) -> Rows:
        return Rows(self.cursor, self.address, name)


class Rows:
    def __init__(self, cursor, address: str, name: str):
        self.cursor = cursor
        self.prefix = (address, name)

    def _run(self, sql: str, *args):
        records._run(self.cursor, sql, (*self.prefix, *args))
        return self.cursor

    def get(self, key: str) -> str | None:
        row = self._run(f"SELECT body FROM {TABLE} WHERE address=%s AND name=%s AND key_id=%s", _digest(key)).fetchone()
        return row[0] if row is not None else None

    def select(self, *, tag: str | None = None) -> dict[str, str]:
        if tag is None:
            cursor = self._run(f"SELECT entry_key,body FROM {TABLE} WHERE address=%s AND name=%s")
        else:
            cursor = self._run(f"SELECT entry_key,body FROM {TABLE} WHERE address=%s AND name=%s AND tag=%s", _digest(tag))
        return dict(cursor.fetchall())

    def get_many(self, keys: Iterable[str]) -> dict[str, str]:
        digests = [_digest(key) for key in keys]
        if not digests:
            return {}
        return dict(self._run(
            f"SELECT entry_key,body FROM {TABLE} WHERE address=%s AND name=%s AND key_id=ANY(%s)", digests,
        ).fetchall())

    def count(self) -> int:
        row = self._run(f"SELECT total FROM {_COUNTS} WHERE address=%s AND name=%s").fetchone()
        return row[0] if row else 0

    def put(self, key: str, body: str, *, tag: str = "", stamp: float = 0) -> None:
        cursor = self._run(
            f"INSERT INTO {TABLE}(address,name,key_id,entry_key,body,tag,stamp) VALUES (%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT DO NOTHING", _digest(key), key, body, _digest(tag), stamp,
        )
        if cursor.rowcount:
            self._change_count(1)
            return
        records._run(self.cursor, f"UPDATE {TABLE} SET body=%s,tag=%s,stamp=%s "
                     "WHERE address=%s AND name=%s AND key_id=%s",
                     (body, _digest(tag), stamp, *self.prefix, _digest(key)))

    def discard(self, key: str) -> bool:
        removed = self._run(f"DELETE FROM {TABLE} WHERE address=%s AND name=%s AND key_id=%s", _digest(key)).rowcount
        if removed:
            self._change_count(-removed)
        return bool(removed)

    def _change_count(self, delta: int) -> None:
        self._run(f"INSERT INTO {_COUNTS}(address,name,total) VALUES (%s,%s,0) ON CONFLICT DO NOTHING")
        records._run(self.cursor, f"UPDATE {_COUNTS} SET total=total+%s WHERE address=%s AND name=%s",
                     (delta, *self.prefix))

    def trim(self, maximum: int) -> None:
        overflow = self.count() - maximum
        if overflow <= 0:
            return
        removed = self._run(
            f"DELETE FROM {TABLE} WHERE address=%s AND name=%s AND key_id IN "
            f"(SELECT key_id FROM {TABLE} WHERE address=%s AND name=%s ORDER BY stamp,key_id LIMIT %s)",
            *self.prefix, overflow,
        ).rowcount
        if removed:
            self._change_count(-removed)

    def seed(self, entries: Iterable[tuple[str, str, str, float]]) -> None:
        """Insert known fresh rows for an import or a disposable fixture."""
        params = ((*self.prefix, _digest(key), key, body, _digest(tag), stamp) for key, body, tag, stamp in entries)
        self.cursor.executemany(
            f"INSERT INTO {TABLE}(address,name,key_id,entry_key,body,tag,stamp) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            params,
        )
        if self.cursor.rowcount:
            self._change_count(self.cursor.rowcount)

    def json_items(self, *, tag: str | None = None) -> dict:
        return {key: json.loads(value) for key, value in self.select(tag=tag).items()}
