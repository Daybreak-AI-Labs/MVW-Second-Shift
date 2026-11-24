"""Transactional submission receipts and serialized attachment quota admission.

Files are staged separately. A durable draft explains any interrupted file/DB
boundary; only admitted submissions may claim execution. Both backends use one
transaction per operation, including pooled PostgreSQL.
"""
from __future__ import annotations

SQLITE_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS attachment_submissions ("
    "submission_key TEXT PRIMARY KEY, tenant_id TEXT, owner TEXT NOT NULL, "
    "goal_id INTEGER NOT NULL UNIQUE REFERENCES goals(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, "
    "state TEXT NOT NULL, detail TEXT NOT NULL, updated_at REAL NOT NULL)"
)
POSTGRES_SCHEMA = SQLITE_SCHEMA.replace("updated_at REAL", "updated_at DOUBLE PRECISION")
