"""Coordinate workers within the one Linux container.

The supervisor owns the deployment lease. Workers elect one timer owner and
share admission slots and temporary request counters on the container's local
filesystem. Durable records still use their existing storage.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager, suppress
from pathlib import Path
from tempfile import TemporaryDirectory

from maverick.control_plane_lease import DASHBOARD_WORKER_ROOT, Slot, try_dashboard_lock
from maverick.control_plane_lease import dashboard_worker_root as active_root

WORKER_COUNT = "MAVERICK_DASHBOARD_WORKERS"
WORKER_ROOT = DASHBOARD_WORKER_ROOT


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

    if os.name != "posix" or not is_postgres_configured():
        raise RuntimeError("Dashboard workers require Linux and PostgreSQL.")
    if active_root() is not None or control_plane_lease.current() is not None:
        raise RuntimeError("Dashboard workers must start from one supervisor.")
    lease = control_plane_lease.acquire(role="dashboard worker supervisor")
    if lease is None:
        raise RuntimeError("Dashboard workers require the deployment's exclusive lease.")
    try:
        with TemporaryDirectory(prefix="second-shift-workers-") as directory:
            root = Path(directory)
            with _rate_connection(root) as conn:
                conn.executescript(
                    "PRAGMA journal_mode=WAL;"
                    "CREATE TABLE hits (namespace text, bucket text, seen real);"
                    "CREATE INDEX hits_recent ON hits(namespace, seen);"
                    "CREATE INDEX hits_bucket ON hits(namespace, bucket);"
                )
            os.environ[WORKER_ROOT] = directory
            try:
                yield
            finally:
                os.environ.pop(WORKER_ROOT, None)
    finally:
        control_plane_lease.release()


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
def _rate_connection(root: Path):
    conn = sqlite3.connect(root / "worker-rates.sqlite3", timeout=1)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def rate_allowed(root: Path, namespace: str, bucket: tuple[str, str], limit: int, max_buckets: int, *,
                 count_hit: bool = True) -> bool:
    """Check and spend one hit in a rolling minute across all the workers."""
    now = time.monotonic()
    identity = json.dumps(bucket, separators=(",", ":"))
    with _rate_connection(root) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM hits WHERE namespace = ? AND seen <= ?", (namespace, now - 60))
        count = conn.execute("SELECT COUNT(*) FROM hits WHERE namespace = ? AND bucket = ?", (namespace, identity)).fetchone()[0]
        if count >= limit:
            return False
        if not count and conn.execute(
                "SELECT COUNT(DISTINCT bucket) FROM hits WHERE namespace = ?", (namespace,)).fetchone()[0] >= max_buckets:
            return False
        if count_hit:
            conn.execute("INSERT INTO hits VALUES (?, ?, ?)", (namespace, identity, now))
        return True
