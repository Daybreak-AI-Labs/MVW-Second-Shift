"""Coordinate workers within the one Linux container.

The supervisor owns the deployment lease. Workers elect one timer owner and
share admission slots and temporary request counters on the container's local
filesystem. Durable records still use their existing storage.
"""
from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
import signal
import sqlite3
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager, suppress
from pathlib import Path
from tempfile import TemporaryDirectory

from maverick.control_plane_lease import DASHBOARD_WORKER_ROOT, Slot, try_dashboard_lock
from maverick.control_plane_lease import dashboard_worker_root as active_root

WORKER_COUNT = "MAVERICK_DASHBOARD_WORKERS"
WORKER_ROOT = DASHBOARD_WORKER_ROOT
_WORKER_PARENT = "MAVERICK_DASHBOARD_WORKER_PARENT"
_PR_SET_PDEATHSIG = 1
_RECORDER_RATE_SHARDS = 32


def worker_count() -> int:
    try:
        count = int(os.environ.get(WORKER_COUNT, "1"))
    except ValueError:
        count = 0
    if not 1 <= count <= 8:
        raise ValueError("Set SECOND_SHIFT_DASHBOARD_WORKERS to a number from 1 to 8.")
    return count


@contextmanager
def supervisor(count: int) -> Iterator[None]:
    if count == 1:
        yield
        return
    from maverick import control_plane_lease
    from maverick.world_model_backends import is_postgres_configured

    if sys.platform != "linux" or not is_postgres_configured():
        raise RuntimeError("Dashboard workers require Linux and PostgreSQL.")
    if active_root() is not None or control_plane_lease.current() is not None:
        raise RuntimeError("Dashboard workers must start from one supervisor.")
    lease = control_plane_lease.acquire(role="dashboard worker supervisor")
    if lease is None:
        raise RuntimeError("Dashboard workers require the deployment's exclusive lease.")
    try:
        with TemporaryDirectory(prefix="second-shift-workers-") as directory:
            root = Path(directory)
            _initialize_rates(root)
            os.environ[WORKER_ROOT] = directory
            os.environ[_WORKER_PARENT] = str(os.getpid())
            try:
                yield
            finally:
                os.environ.pop(WORKER_ROOT, None)
                os.environ.pop(_WORKER_PARENT, None)
    finally:
        control_plane_lease.release()


def guard_supervisor() -> None:
    """Have Linux stop an orphan worker before it can write under a lost lease."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise RuntimeError("The dashboard worker cannot watch its supervisor.")
    # Cover a supervisor exit before prctl set the signal.
    if str(os.getppid()) != os.environ.get(_WORKER_PARENT):
        raise RuntimeError("The dashboard worker's supervisor is unavailable.")


def take_slot(root: Path, namespace: str, slots: int) -> Slot | None:
    first = os.getpid() % slots
    for offset in range(slots):
        slot = (first + offset) % slots
        if claim := try_dashboard_lock(root, f"{namespace}-{slot}"):
            return claim
    return None


@asynccontextmanager
async def timers(factories: tuple[Callable, ...]) -> AsyncIterator[None]:
    """Run timer loops until shutdown and await cancellation before releasing ownership."""
    tasks = [asyncio.create_task(factory()) for factory in factories]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task


async def lead_timers(root: Path, factories: tuple[Callable, ...], *, interval: float = 0.5) -> None:
    while (slot := take_slot(root, "timer-leader", 1)) is None:
        await asyncio.sleep(interval)
    try:
        async with timers(factories):
            await asyncio.Future()
    finally:
        slot.release()


@contextmanager
def _rate_connection(root: Path, shard: int | None = None):
    file = "worker-rates.sqlite3" if shard is None else f"recorder-rates-{shard}.sqlite3"
    conn = sqlite3.connect(root / file, timeout=1)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _initialize_rates(root: Path) -> None:
    for shard in (None, *range(_RECORDER_RATE_SHARDS)):
        with _rate_connection(root, shard) as conn:
            conn.executescript(
                "PRAGMA journal_mode=WAL;"
                "CREATE TABLE rate_windows (namespace text, bucket text, latest real, hits text, "
                "PRIMARY KEY (namespace, bucket)) WITHOUT ROWID;"
                "CREATE INDEX window_expiry ON rate_windows(namespace, latest);"
            )


def rate_allowed(root: Path, namespace: str, bucket: tuple[str, str], limit: int, max_buckets: int, *,
                 count_hit: bool = True) -> bool:
    """Check and spend one hit in a rolling minute across all the workers."""
    identity = json.dumps(bucket, separators=(",", ":"))
    shard = None
    if namespace == "ekko" and max_buckets >= _RECORDER_RATE_SHARDS:
        # All workers send a bucket to the same file. Independent recorders
        # do not queue for one SQLite writer or delay the agent gateway.
        digest = hashlib.blake2s(identity.encode(), digest_size=4).digest()
        shard = int.from_bytes(digest, "big") % _RECORDER_RATE_SHARDS
        capacity, remainder = divmod(max_buckets, _RECORDER_RATE_SHARDS)
        max_buckets = capacity + int(shard < remainder)
    with _rate_connection(root, shard) as conn:
        # A preflight can inspect the latest committed window while another
        # worker spends a hit. Counted requests still update atomically.
        if count_hit and shard is not None:
            # Counters live for the lifetime of the worker group. WAL commits
            # remain visible across workers without a disk flush on every call.
            conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("BEGIN IMMEDIATE" if count_hit else "BEGIN")
        now = time.monotonic()
        cutoff = now - 60
        row = conn.execute(
            "SELECT hits FROM rate_windows WHERE namespace = ? AND bucket = ? AND latest > ?",
            (namespace, identity, cutoff),
        ).fetchone()
        hits = [stamp for stamp in json.loads(row[0]) if stamp > cutoff] if row else []
        if len(hits) >= limit:
            return False
        if not hits and conn.execute(
            "SELECT 1 FROM rate_windows WHERE namespace = ? AND latest > ? LIMIT 1 OFFSET ?",
            (namespace, cutoff, max_buckets - 1),
        ).fetchone():
            return False
        if count_hit:
            conn.execute("DELETE FROM rate_windows WHERE namespace = ? AND latest <= ?", (namespace, cutoff))
            conn.execute(
                "INSERT INTO rate_windows VALUES (?, ?, ?, ?) "
                "ON CONFLICT(namespace, bucket) DO UPDATE SET latest = excluded.latest, hits = excluded.hits",
                (namespace, identity, now, json.dumps([*hits, now], separators=(",", ":"))),
            )
        return True
