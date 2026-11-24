"""Decision requests: a governed run asks a person to choose, then continues.

A run that meets a judgment call it should not make alone calls the
``request_decision`` tool with a question, two to five options (a short label
and what happens if chosen), the option it recommends and why, and the area the
choice concerns. This module stores that request, pauses the run, lets an
authorized person choose an option, and gives the choice back to the run as a
structured record.

What it reuses:

* The pause is the ``ask_user`` pause: the agent loop ends the turn as
  ``blocked_on_user``, the orchestrator marks the goal ``blocked`` and ends the
  episode, so a waiting run holds no process and spends nothing.
* The restart is the clarification restart (:class:`maverick.chat_threads.
  ChatThreads`): the answer and the move back to ``pending`` commit in one
  transaction, under the same task-handoff, conversation and outcome-pilot
  checks a question answer uses.
* Who may answer reuses the approval rules: the run's owner or a workspace
  administrator, and an area listed in ``[approval] decision_admin_areas``
  needs an administrator. Whether the person who started the run may answer
  such a decision follows ``[approval] separate_approver``, exactly as for a
  high-risk approval: by default someone else answers whenever another
  administrator could.
* Every request, answer and expiry goes to the audit log
  (:func:`maverick.audit.audit_event`) with the actor, and to the task's
  timeline.

The rows live in the world database (``decision_requests``, migration 55 in
both backends), scoped through their goal like ``questions``.

Configuration (``[approval]``)::

    decision_areas = ["security", "workspace_boundaries", ...]   # see DEFAULT_AREAS
    decision_admin_areas = ["governance"]
    decision_expiry_hours = 72

A workspace overlay may add areas to either list but never remove one. The
area list is shown to the model so it knows when to ask; nothing here detects
every such choice by itself.
"""
from __future__ import annotations

SQLITE_SCHEMA: list[str] = [
    "CREATE TABLE IF NOT EXISTS decision_requests ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " goal_id INTEGER NOT NULL REFERENCES goals(id) ON DELETE CASCADE,"
    " area TEXT NOT NULL, question TEXT NOT NULL, options TEXT NOT NULL,"
    " recommended INTEGER NOT NULL, reason TEXT NOT NULL,"
    " admin_required INTEGER NOT NULL DEFAULT 0, requested_by TEXT NOT NULL DEFAULT '',"
    " status TEXT NOT NULL DEFAULT 'open', created_at REAL NOT NULL,"
    " expires_at REAL NOT NULL, chosen INTEGER, note TEXT, decided_by TEXT,"
    " decided_at REAL, resume_token TEXT, resume_dispatched_at REAL)",
    "CREATE INDEX IF NOT EXISTS idx_decision_requests_goal ON decision_requests(goal_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_decision_requests_open ON decision_requests(status, expires_at)",
]
POSTGRES_SCHEMA: list[str] = [
    statement.replace("id INTEGER PRIMARY KEY AUTOINCREMENT", "id SERIAL PRIMARY KEY")
    .replace(" REAL", " DOUBLE PRECISION")
    .replace("idx_decision_requests_", "idx_pg_decision_requests_")
    for statement in SQLITE_SCHEMA
]


__all__ = [
]
