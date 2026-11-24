"""A record of every approval check, for previewing a threshold change later.

Each time the approval gate (:mod:`maverick.safety.consent`) decides an
action, one row says when, in which workspace, at which risk level, what kind
of action, which agent or specialist was working, and the outcome: allowed
without asking, asked a person, or refused. Never the content, the arguments
or the command. The rows live in the world database (``approval_checks``),
so a Postgres deployment shares them across replicas.

Configuration (``[approval]``)::

    record_checks = true          # default on
    check_retention_days = 90     # older rows are pruned in bounded batches

Recording never changes a decision: a failure to record is logged and the
gate's answer stands.
"""
from __future__ import annotations

SQLITE_SCHEMA: list[str] = [
    "CREATE TABLE IF NOT EXISTS approval_checks ("
    " id TEXT PRIMARY KEY, workspace TEXT NOT NULL DEFAULT '',"
    " checked_at REAL NOT NULL, risk TEXT NOT NULL DEFAULT '',"
    " action_kind TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL DEFAULT '',"
    " outcome TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_approval_checks_when"
    " ON approval_checks(workspace, checked_at)",
]
POSTGRES_SCHEMA: list[str] = [s.replace(" REAL", " DOUBLE PRECISION") for s in SQLITE_SCHEMA]


__all__ = [
]
