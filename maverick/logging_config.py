"""Structured logging for production deployments.

Set ``MAVERICK_LOG_FORMAT=json`` to emit one JSON object per line --
parseable by Loki/CloudWatch/Datadog/etc. Default stays human-readable.

Set ``MAVERICK_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR`` (default INFO).

Per-goal trace context is propagated through ``contextvars`` so every
log line emitted inside ``run_goal`` is automatically tagged with the
goal id, conversation id, and channel without callers passing it
through every function.

Crash-safe copy (opt-in, ``[logging] crash_log`` or ``MAVERICK_CRASH_LOG=1``):
warnings and errors are also written, one fsync'd line each, to
``logs/crash-only.jsonl`` under Second Shift's data folder through
:class:`maverick.crash_only_log.CrashOnlyLog`, so the records describing a
crash survive the crash. ``[logging] crash_only_fsync = "never"`` keeps the
format but trades per-line durability for speed. Off by default.
"""
from __future__ import annotations

import contextvars


_goal_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "maverick_goal_id", default=None,
)


def current_goal_id() -> int | None:
    """The goal id bound to the current async/sync task, or None outside a goal.

    Lets non-logging callers (e.g. the consent gate, which attributes a queued
    approval to the requesting principal) identify the executing goal without
    re-plumbing the id through every call site. Propagates across
    ``asyncio.to_thread`` because that copies the context."""
    return _goal_id_var.get()


_configured = False
