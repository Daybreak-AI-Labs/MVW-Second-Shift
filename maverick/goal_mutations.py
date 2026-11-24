"""Atomic, revision-bound human edits shared by the dashboard and authorized tools."""
from __future__ import annotations

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS goal_mutation_receipts ("
    "goal_id INTEGER NOT NULL REFERENCES goals(id) ON DELETE CASCADE, kind TEXT NOT NULL, "
    "operation_id TEXT NOT NULL, actor TEXT NOT NULL, request_hash TEXT NOT NULL, "
    "receipt TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, "
    "PRIMARY KEY(goal_id, kind, operation_id, actor))"
)
