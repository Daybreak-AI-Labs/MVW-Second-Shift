"""Device keys for the Ekko recorder: one access key per enrolled device.

A person who has enrolled a device can create one key for it. The recorder on
that computer presents the key to read its instructions and to hand over
activities. This module mints the key and keeps what the server needs to
recognise it again: a hash of the key, the sealed record of what it is bound to
(the workspace, the person, the device name and the enrollment it was created
under), a fingerprint of the computer account that first handed over, and when
the recorder was last heard from.

It does not decide whether anything is accepted. The dashboard hand-over routes
re-check the enrollment, the session and the settings on every call; a key
found here only says who is asking. It never stores a key, an account name or
an activity, and it has no way to list people: every read needs the key itself
or the exact workspace, person and device.

The index is one private SQLite file for the whole installation, outside the
workspace folders, because a recorder presents nothing but its key: the server
must find the record before it knows the workspace. Each record is sealed with
its own workspace's key, so the file alone names nobody.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

KEY_PREFIX = "ekr_"
_KEY_RE = re.compile(r"^ekr_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
_HASH_PREFIX = "sha256:"
# Compared against when no record matches, so a refusal takes the same work
# whether or not the key's public part exists.
_NO_RECORD_HASH = _HASH_PREFIX + "0" * 64
_ACCOUNT_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECORD_BYTES = 4_096
#: The recorder asks for instructions every few seconds; "last heard from" is
#: written at most this often.
HEARD_WRITE_SECONDS = 30.0
#: A refused hand-over is put in the activity record at most this often per key.
REFUSAL_AUDIT_SECONDS = 600.0


class DeviceKeyError(RuntimeError):
    """A key record cannot be read or trusted. Callers accept nothing."""


@dataclass(frozen=True)
class DeviceKey:
    """What one live key is bound to. Never the key or its hash."""

    key_id: str
    tenant: str | None
    owner: str
    device_id: str
    enrollment: str
    created_at: float
    heard_at: float | None
    account_bound: bool


def hash_key(key: str) -> str:
    """The stored form of a key: ``sha256:<hex>``. The key itself is never kept."""
    return _HASH_PREFIX + hashlib.sha256((key or "").encode("utf-8", "surrogatepass")).hexdigest()


def enrollment_fingerprint(enrollment) -> str:
    """Name one exact enrollment. Enrolling again gives a different value."""
    body = (
        f"ekko:device-key-enrollment:v1:{enrollment.policy_digest}:"
        f"{float(enrollment.enrolled_at)!r}:{float(enrollment.expires_at)!r}"
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _digest(kind: str, *parts: str) -> str:
    body = json.dumps([kind, *parts], separators=(",", ":"))
    return hashlib.sha256(f"ekko:device-key:v1:{body}".encode()).hexdigest()


def _device_scope(tenant: str | None, owner: str, device_id: str) -> str:
    return _digest("device", tenant or "", owner, device_id)


def _owner_scope(tenant: str | None, owner: str) -> str:
    return _digest("owner", tenant or "", owner)


def _account_hash(key_id: str, account: str) -> str:
    return _digest("account", key_id, account)


def _path() -> Path:
    from .paths import data_dir

    return data_dir("ekko", "device-keys.sqlite3", tenant=None)


@contextlib.contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    from .file_lock import ensure_private_directory, ensure_private_file

    path = _path()
    ensure_private_directory(path.parent)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    ensure_private_file(path, 0o600)
    conn = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ekko_device_keys (
                key_id TEXT PRIMARY KEY,
                device_scope TEXT NOT NULL UNIQUE,
                owner_scope TEXT NOT NULL,
                tenant TEXT,
                key_hash TEXT NOT NULL,
                record BLOB NOT NULL,
                account_hash TEXT NOT NULL DEFAULT '',
                heard_at REAL,
                refusal_at REAL
            )
        """)
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()


def _seal(tenant: str | None, record: dict) -> bytes:
    from .tenant.kms import seal_for_tenant

    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return seal_for_tenant(tenant or "__local__", body)


def _decode(row: sqlite3.Row) -> DeviceKey:
    """Open one row, or refuse it. The sealed record must agree with every
    column beside it, so a row cannot be pointed at another person or key."""
    from .tenant.kms import unseal_for_tenant

    tenant = row["tenant"]
    blob = bytes(row["record"])
    try:
        if len(blob) > _MAX_RECORD_BYTES:
            raise ValueError("record too large")
        record = json.loads(unseal_for_tenant(tenant or "__local__", blob))
        key = DeviceKey(
            key_id=str(record["key_id"]),
            tenant=tenant,
            owner=str(record["owner"]),
            device_id=str(record["device_id"]),
            enrollment=str(record["enrollment"]),
            created_at=float(record["created_at"]),
            heard_at=float(row["heard_at"]) if row["heard_at"] is not None else None,
            account_bound=bool(row["account_hash"]),
        )
        agrees = (
            set(record) == {"version", "key_id", "key_hash", "owner", "device_id", "enrollment", "created_at"}
            and record["version"] == 1
            and key.key_id == row["key_id"]
            and hmac.compare_digest(str(record["key_hash"]), str(row["key_hash"]))
            and row["device_scope"] == _device_scope(tenant, key.owner, key.device_id)
            and row["owner_scope"] == _owner_scope(tenant, key.owner)
        )
    except Exception as exc:
        # One content-free refusal whatever failed: the workspace key, the
        # sealed bytes or the record's shape.
        raise DeviceKeyError("the recorder key record could not be read") from exc
    if not agrees:
        raise DeviceKeyError("the recorder key record does not match its entry")
    return key


def create(
    owner: str, device_id: str, *, tenant: str | None, enrollment: str, now: float | None = None,
) -> tuple[str, DeviceKey]:
    """Mint the key for one enrolled device and return it, once.

    A device has one live key: creating a new one removes the earlier record in
    the same step, so the earlier key stops working at once. The account
    fingerprint starts empty again with the new key.
    """
    key_id = secrets.token_hex(8)
    key = f"{KEY_PREFIX}{key_id}_{secrets.token_urlsafe(32)}"
    created_at = time.time() if now is None else float(now)
    key_hash = hash_key(key)
    record = _seal(tenant, {
        "version": 1, "key_id": key_id, "key_hash": key_hash, "owner": owner,
        "device_id": device_id, "enrollment": enrollment, "created_at": created_at,
    })
    scope = _device_scope(tenant, owner, device_id)
    with _transaction() as conn:
        conn.execute("DELETE FROM ekko_device_keys WHERE device_scope=?", (scope,))
        conn.execute(
            "INSERT INTO ekko_device_keys(key_id,device_scope,owner_scope,tenant,key_hash,record) "
            "VALUES(?,?,?,?,?,?)",
            (key_id, scope, _owner_scope(tenant, owner), tenant, key_hash, record),
        )
    return key, DeviceKey(key_id, tenant, owner, device_id, enrollment, created_at, None, False)


def find(key: str) -> DeviceKey | None:
    """The record a presented key belongs to, or ``None``.

    The hash is compared in constant time, and compared even when no record has
    that public part. :class:`DeviceKeyError` means a record matched but could
    not be read: the caller refuses, it does not fall back.
    """
    match = _KEY_RE.fullmatch(key or "")
    if not _path().exists():
        return None
    row = None
    if match is not None:
        with _connect() as conn:
            row = conn.execute("SELECT * FROM ekko_device_keys WHERE key_id=?", (match.group(1),)).fetchone()
    stored = str(row["key_hash"]) if row is not None else _NO_RECORD_HASH
    if not hmac.compare_digest(stored.encode(), hash_key(key).encode()) or row is None:
        return None
    return _decode(row)


def for_device(owner: str, device_id: str, *, tenant: str | None) -> DeviceKey | None:
    """The live key record for one person's device, if there is one."""
    if not _path().exists():
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM ekko_device_keys WHERE device_scope=?", (_device_scope(tenant, owner, device_id),),
        ).fetchone()
    return _decode(row) if row is not None else None


def device_names(owner: str, *, tenant: str | None) -> list[str]:
    """The names of this person's devices that have a recorder key."""
    if not _path().exists():
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM ekko_device_keys WHERE owner_scope=?", (_owner_scope(tenant, owner),),
        ).fetchall()
    names = []
    for row in rows:
        try:
            names.append(_decode(row).device_id)
        except DeviceKeyError:
            continue  # shown nowhere; the hand-over routes refuse it
    return sorted(names)


def revoke(owner: str, device_id: str, *, tenant: str | None) -> bool:
    """Remove the key for one person's device. True when there was one.

    Removal never needs the record to be readable, so a damaged record can
    always be cleared.
    """
    if not _path().exists():
        return False
    with _transaction() as conn:
        conn.execute("DELETE FROM ekko_device_keys WHERE device_scope=?", (_device_scope(tenant, owner, device_id),))
        return conn.execute("SELECT changes()").fetchone()[0] == 1


def forget(key: DeviceKey) -> None:
    """Remove exactly this key's record: its enrollment has ended."""
    with _transaction() as conn:
        conn.execute("DELETE FROM ekko_device_keys WHERE key_id=?", (key.key_id,))


def note_heard(key: DeviceKey, *, now: float) -> None:
    """Remember that the recorder called, at most every ``HEARD_WRITE_SECONDS``."""
    if key.heard_at is not None and now - key.heard_at < HEARD_WRITE_SECONDS:
        return
    with _transaction() as conn:
        conn.execute("UPDATE ekko_device_keys SET heard_at=? WHERE key_id=?", (float(now), key.key_id))


def account_matches(key: DeviceKey, account: str) -> bool | None:
    """Whether ``account`` is the one this key first handed over from.

    ``None`` while nothing has been handed over with this key yet.
    """
    if not _ACCOUNT_RE.fullmatch(account or ""):
        return False
    with _connect() as conn:
        row = conn.execute("SELECT account_hash FROM ekko_device_keys WHERE key_id=?", (key.key_id,)).fetchone()
    if row is None:
        return False
    if not row["account_hash"]:
        return None
    return hmac.compare_digest(str(row["account_hash"]), _account_hash(key.key_id, account))


def bind_account(key: DeviceKey, account: str) -> bool:
    """Record the first account fingerprint; afterwards only compare.

    True when ``account`` is, or has just become, the recorded one. Only a
    digest of the fingerprint is kept.
    """
    if not _ACCOUNT_RE.fullmatch(account or ""):
        return False
    digest = _account_hash(key.key_id, account)
    with _transaction() as conn:
        row = conn.execute("SELECT account_hash FROM ekko_device_keys WHERE key_id=?", (key.key_id,)).fetchone()
        if row is None:
            return False
        if not row["account_hash"]:
            conn.execute("UPDATE ekko_device_keys SET account_hash=? WHERE key_id=?", (digest, key.key_id))
            return True
        return hmac.compare_digest(str(row["account_hash"]), digest)


def refusal_due(key: DeviceKey, *, now: float) -> bool:
    """True when a refused hand-over should be written to the activity record.

    A recorder that keeps trying is recorded at most every
    ``REFUSAL_AUDIT_SECONDS``, so it cannot fill the record.
    """
    with _transaction() as conn:
        conn.execute(
            "UPDATE ekko_device_keys SET refusal_at=? WHERE key_id=? AND (refusal_at IS NULL OR refusal_at<=?)",
            (float(now), key.key_id, float(now) - REFUSAL_AUDIT_SECONDS),
        )
        return conn.execute("SELECT changes()").fetchone()[0] == 1


__all__ = [
    "DeviceKey",
    "DeviceKeyError",
    "KEY_PREFIX",
    "account_matches",
    "bind_account",
    "create",
    "device_names",
    "enrollment_fingerprint",
    "find",
    "for_device",
    "forget",
    "hash_key",
    "note_heard",
    "refusal_due",
    "revoke",
]
