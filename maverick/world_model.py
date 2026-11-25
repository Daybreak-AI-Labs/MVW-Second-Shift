"""Persistent world model. SQLite + per-connection WAL.

Reliability:
  - PRAGMA journal_mode=WAL so the agent process (writer) and dashboard
    process (reader) don't deadlock on each other.
  - PRAGMA busy_timeout=5000 so concurrent commits retry briefly
    instead of raising OperationalError.
  - check_same_thread=False so FastAPI's threadpool can share the connection.
  - Indexes on goals(status) and goals(updated_at) for the dashboard's
    `list goals by status` and `active_goal()` queries.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import fields
from pathlib import Path
from typing import Any

from .approval_checks import SQLITE_SCHEMA as _APPROVAL_CHECK_SCHEMA
from .attachment_submissions import SQLITE_SCHEMA as _ATTACHMENT_SUBMISSION_SCHEMA
from .deadline_alerts import SQLITE_SCHEMA as _DEADLINE_ALERT_SCHEMA
from .decision_requests import SQLITE_SCHEMA as _DECISION_REQUEST_SCHEMA
from .event_admission import SQLITE_SCHEMA as _EVENT_ADMISSION_SCHEMA
from .event_admission import (
    EventRegistryUnavailable,
    LegacyEventGoalHeld,
    compatible_event_goal,
    execution_binding_lock,
)
from .file_lock import (
    atomic_create_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    prepare_private_directory,
)
from .goal_mutations import SCHEMA as _GOAL_MUTATION_SCHEMA
from .metadata_history import SQLITE_INDEXES as _HISTORY_INDEXES
from .paths import bind_tenant_namespace, current_tenant_id, data_dir
from .personal_alert_revisions import SQLITE_MIGRATION as _PERSONAL_ALERT_MIGRATION
from .webhook_subscriptions import SQLITE_SCHEMA as _WEBHOOK_SUBSCRIPTION_SCHEMA
from .world_records import AgentSpendGroup
from .world_records import Approval as Approval
from .world_records import ApprovalAuditEvent as ApprovalAuditEvent
from .world_records import EpisodeSpend as EpisodeSpend
from .world_records import Goal as Goal

log = logging.getLogger(__name__)

# ``DEFAULT_DB`` remains a public override hook for embedders and tests, but
# the built-in default must be resolved at *call time*.  A process can import
# this module while handling tenant A and later serve tenant B (or the shared
# single-tenant root); using the import-time path in that later request would
# cross the tenant boundary.  Identity, rather than equality, distinguishes an
# intentional override from the untouched compatibility constant.
_INITIAL_DEFAULT_DB = data_dir("world.db")
DEFAULT_DB = _INITIAL_DEFAULT_DB
SCHEMA_VERSION = 56
DEFAULT_BUSY_TIMEOUT_MS = 5000
WAL_SWITCH_BUSY_TIMEOUT_MS = 50
WAL_SWITCH_RETRY_SECONDS = 5.0

# Valid PRAGMA synchronous levels (we don't expose OFF — corruption risk).
_SYNC_MODES = {"NORMAL", "FULL", "EXTRA"}


def _synchronous_mode() -> str:
    """The PRAGMA synchronous level: ``MAVERICK_WORLD_SYNCHRONOUS`` /
    ``[world_model] synchronous`` (NORMAL default). FULL/EXTRA make every commit
    durable (no acked-row loss on OS crash) at a write-latency cost."""
    raw = os.environ.get("MAVERICK_WORLD_SYNCHRONOUS")
    if not raw:
        try:
            from .config import load_config
            raw = ((load_config() or {}).get("world_model") or {}).get("synchronous")
        except Exception:
            raw = None
    mode = str(raw or "NORMAL").strip().upper()
    return mode if mode in _SYNC_MODES else "NORMAL"


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES goals(id),
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    deadline REAL,
    result TEXT,
    owner TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    project_id INTEGER
);

-- v19 projects ("matters"): a workspace grouping related goals (a close cycle,
-- an audit, a deal). name + description are encrypted at rest like goal content;
-- owner/domain/status are plaintext for listing + filtering. Goals point at one
-- via goals.project_id (nullable; a goal need not belong to a project).
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    owner TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at REAL NOT NULL
);

-- v20 share links: a revocable, expiring read-only link to a goal's
-- deliverable for someone without a dashboard login. The token is random and
-- only its SHA-256 is stored (like a password-reset token), so the DB never
-- holds anything that grants access; the clear token is shown to the creator
-- exactly once.
CREATE TABLE IF NOT EXISTS share_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    token_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    expires_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_goals_status     ON goals(status);
CREATE INDEX IF NOT EXISTS idx_goals_updated_at ON goals(updated_at);

CREATE TABLE IF NOT EXISTS goal_origins (
    goal_id INTEGER PRIMARY KEY REFERENCES goals(id),
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_goal_origins_ref ON goal_origins(kind, ref);

-- v16 deliverable sign-off: a human's certify/reject decision on a finished,
-- gated deliverable (the review a pack's output-contract gate calls for). One
-- authoritative current decision per goal; the note is encrypted at rest like
-- other free-text. This is the governed hand-off: agents draft, humans certify.
CREATE TABLE IF NOT EXISTS signoffs (
    goal_id INTEGER PRIMARY KEY REFERENCES goals(id),
    decision TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    note TEXT,
    created_at REAL NOT NULL
);

-- v18 artifacts: versioned, kind-tagged deliverable artifacts a goal produces
-- (markdown / code / table / text), distinct from the single goal.result blob.
-- Re-emitting the same (goal_id, title) appends a new version; title + content
-- are encrypted at rest like other agent output. The render kind drives how the
-- dashboard presents it.
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    kind TEXT NOT NULL DEFAULT 'text',
    title TEXT,
    content TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_goal ON artifacts(goal_id);

CREATE TABLE IF NOT EXISTS episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    started_at REAL NOT NULL,
    ended_at REAL,
    summary TEXT,
    outcome TEXT,
    cost_dollars REAL DEFAULT 0,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    tool_calls INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0,
    cache_write_tokens INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_episodes_ended_at ON episodes(ended_at);

CREATE TABLE IF NOT EXISTS facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source_episode_id INTEGER REFERENCES episodes(id),
    updated_at REAL NOT NULL,
    -- v17 Memory Guard provenance (plaintext metadata; the value stays sealed).
    -- source = who authored this fact; trust_tier = maverick.memory_guard.TrustTier
    -- (3=first-party/operator default ... 0=external/untrusted); sensitivity label.
    source TEXT NOT NULL DEFAULT '',
    trust_tier INTEGER NOT NULL DEFAULT 3,
    sensitivity TEXT NOT NULL DEFAULT 'internal',
    UNIQUE(key)
);

-- v17 temporal memory: a bitemporal history of every fact value. `facts` keeps
-- the single CURRENT value (UNIQUE(key)); this table records each value's
-- validity window so "what did we believe on date X, and why" is answerable --
-- non-destructive evolution instead of overwrite. `value` is sealed at rest like
-- facts.value; the window/provenance columns are plaintext so they stay queryable
-- under encryption. Only written when [memory] temporal is enabled.
CREATE TABLE IF NOT EXISTS fact_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source_episode_id INTEGER REFERENCES episodes(id),
    valid_from REAL NOT NULL,
    valid_to REAL,
    source TEXT NOT NULL DEFAULT '',
    trust_tier INTEGER NOT NULL DEFAULT 3,
    sensitivity TEXT NOT NULL DEFAULT 'internal'
);

CREATE INDEX IF NOT EXISTS idx_fact_history_key ON fact_history(key, valid_from);

CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    question TEXT NOT NULL,
    asked_at REAL NOT NULL,
    answer TEXT,
    answered_at REAL
);

-- v9 approval queue: high-risk actions parked by safety.consent in
-- 'dashboard' mode. The consent path inserts a 'pending' row and polls
-- status; the dashboard /approvals page flips it to approved/denied.
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    risk TEXT NOT NULL DEFAULT 'medium',
    scope TEXT,
    detail TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at REAL NOT NULL,
    decided_at REAL,
    claimed_by TEXT,
    claimed_at REAL,
    decided_by TEXT,
    approvals_required INTEGER NOT NULL DEFAULT 1,
    requested_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, id);

-- v21 N-of-M dual control: one row per (approval, approver), so the PK enforces
-- a given approver counting once toward the quorum (segregation of duties).
CREATE TABLE IF NOT EXISTS approval_signoffs (
    approval_id INTEGER NOT NULL,
    approver    TEXT NOT NULL,
    decision    TEXT NOT NULL,
    decided_at  REAL NOT NULL,
    note        TEXT,
    PRIMARY KEY (approval_id, approver)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS goal_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    agent TEXT NOT NULL,
    kind TEXT NOT NULL,
    content TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_goal_events_goal_id_id ON goal_events(goal_id, id);
CREATE INDEX IF NOT EXISTS idx_goal_events_ts          ON goal_events(ts);

-- v4 multi-turn conversations: one thread per channel user.
-- (channel, user_id) is the natural key, so the same iMessage user
-- across separate Second Shift goals lands in a single conversation.
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(channel, user_id)
);

CREATE INDEX IF NOT EXISTS idx_conversations_last_seen ON conversations(last_seen);

CREATE TABLE IF NOT EXISTS turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id),
    goal_id INTEGER REFERENCES goals(id),
    role TEXT NOT NULL,     -- 'user' | 'assistant'
    content TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_turns_conv_id ON turns(conversation_id, id);

-- v5 attachments: files/images uploaded with a goal.
-- The actual bytes live on disk under ~/.maverick/attachments/<goal>/<sha>;
-- this row records the metadata and lets the agent enumerate them.
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachments_goal_id ON attachments(goal_id);

-- v6 channel idempotency: Twilio / iMessage / other channels retry
-- webhooks on non-2xx (or slow handlers). Without a dedup key the same
-- inbound message triggers N goal runs and N API spends.
CREATE TABLE IF NOT EXISTS processed_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    external_id TEXT NOT NULL,
    goal_id INTEGER REFERENCES goals(id),
    seen_at REAL NOT NULL,
    UNIQUE(channel, external_id)
);

-- v22 cluster-wide killswitch: a shared halt the dashboard arms and every
-- replica's killswitch.check() consults, so an emergency stop propagates across
-- the fleet (the in-process flag + local HALT file only stop the replica that
-- served the request). Untenanted on purpose -- a global emergency stop is not
-- per-tenant; ``scope=''`` is the global row.
CREATE TABLE IF NOT EXISTS halt (
    scope    TEXT PRIMARY KEY,
    reason   TEXT,
    source   TEXT,
    armed_by TEXT,
    armed_at REAL NOT NULL
);

-- v23 cluster-wide provider spend ledger: a shared per-(period, provider) total
-- so the provider_cost_cap ceiling is enforced across the fleet, not per-host.
-- The host-local JSON ledger (provider_spend.json) is per-host and lets N
-- replicas each spend up to the cap; on a shared backend this row is the single
-- authoritative total.
CREATE TABLE IF NOT EXISTS provider_spend (
    period_key TEXT NOT NULL,
    provider   TEXT NOT NULL,
    dollars    REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (period_key, provider)
);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    content, content='messages', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
END;

-- External-content FTS5 requires the delete/update triggers too, or the
-- shadow index drifts out of sync with `messages` on any DELETE/UPDATE
-- (purge already deletes messages), leaving search matching stale/missing rows.
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content)
    VALUES('delete', old.id, old.content);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content)
    VALUES('delete', old.id, old.content);
    INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
END;

-- v8 hot-query indexes: cover the read paths listed in
-- docs/performance/world-model-indexes.md. MIGRATIONS[8] repeats them so
-- existing databases pick them up on next open.
CREATE INDEX IF NOT EXISTS idx_episodes_goal_started
    ON episodes(goal_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_episodes_started
    ON episodes(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_goals_status_updated
    ON goals(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_goals_parent
    ON goals(parent_id, created_at);

-- v25 fleet learning store: the self-harness addenda / provenance / transfer
-- tried-memory as shared tables, so a multi-host fleet learns as one. Written
-- only when [self_harness] store = "world"; empty tables otherwise.
CREATE TABLE IF NOT EXISTS harness_addenda (
    key        TEXT PRIMARY KEY,
    block      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS harness_line_meta (
    line_id    TEXT PRIMARY KEY,
    record     TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS harness_transfer_tried (
    line_id TEXT PRIMARY KEY,
    ts      REAL NOT NULL
);

-- v26 fleet learning store, eval corpus: live cases, harvest pending and
-- reject memory, plus "extra" rows preserving a live file's non-list top-level
-- entries. seq preserves row order (review indexes are positional). Written
-- only when [self_harness] store = "world".
CREATE TABLE IF NOT EXISTS harness_corpus (
    kind TEXT NOT NULL,
    key  TEXT NOT NULL,
    seq  INTEGER NOT NULL,
    row  TEXT NOT NULL,
    PRIMARY KEY (kind, key, seq)
);
"""


def _bootstrap_schema(conn: sqlite3.Connection) -> str:
    """Do not recreate v49's retired derived index from the immutable v1 seed.

    From v49 on, the seed is applied without its message-search block: from the
    ``messages_fts`` virtual table up to the first v8 index that follows it.
    """
    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone():
        row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        if row and row[0] >= 49:
            start = SCHEMA.index("CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts")
            end = SCHEMA.index("CREATE INDEX IF NOT EXISTS idx_episodes_goal_started", start)
            return SCHEMA[:start] + SCHEMA[end:]
    return SCHEMA


MIGRATIONS: dict[int, list[str]] = {
    # v56: Postgres row policies for the tables that had none. SQLite has no
    # row-level security (each workspace has its own file); this keeps the
    # two schema heads aligned.
    56: [],
    # v55: a run's question for a person with options and a recommendation
    # (maverick.decision_requests). Rows are scoped through their goal.
    55: _DECISION_REQUEST_SCHEMA,
    # v54: a running goal's liveness heartbeat has its own timestamp, so it no
    # longer changes ``updated_at``, the version a reviewed Stop or edit binds.
    54: ["ALTER TABLE goals ADD COLUMN heartbeat_at REAL"],
    # v53: an external agent's run report key binds one goal. The unique
    # index makes a concurrent retry with the same key reuse that goal.
    53: ["CREATE UNIQUE INDEX IF NOT EXISTS idx_goal_origins_external_run "
         "ON goal_origins(ref) WHERE kind = 'external_run'"],
    # v52: Postgres stores per-tenant rebinding completion in the database.
    # SQLite retains its adjacent marker; the table keeps schema heads aligned.
    52: ["CREATE TABLE IF NOT EXISTS encryption_migrations ("
         "scope TEXT PRIMARY KEY, tenant_id TEXT, migrated_at REAL NOT NULL, "
         "CHECK (scope = CASE WHEN tenant_id IS NULL THEN 'n:' ELSE 't:' || tenant_id END))"],
    # v51: which decisions can still be undone. Only a request a waiting task
    # holds ("open") can be; the task marks it "settled" when it acts on it.
    51: ["ALTER TABLE approvals ADD COLUMN undo_hold TEXT"],
    # v50: ordered per-task question reads avoid scanning unrelated history.
    50: ["CREATE INDEX IF NOT EXISTS idx_questions_goal_id ON questions(goal_id, id)"],
    # v49: retire only unused derived message-search storage. Authoritative
    # messages and conversation turns are untouched; the exact SQL is governed.
    49: [
        "DROP TRIGGER IF EXISTS messages_ai",
        "DROP TRIGGER IF EXISTS messages_ad",
        "DROP TRIGGER IF EXISTS messages_au",
        "DROP TABLE IF EXISTS messages_fts",
    ],
    # v48: one row per approval-gate decision (no content), for previewing a
    # threshold change later (maverick.approval_checks).
    48: _APPROVAL_CHECK_SCHEMA,
    # Reconcile both draft histories without changing their earlier fingerprints.
    # The teardown draft used v42 for these tables, so its databases may have
    # skipped the companion draft's v42 receipt table. Ensure both sets at v47.
    47: [
        _GOAL_MUTATION_SCHEMA,
        *_WEBHOOK_SUBSCRIPTION_SCHEMA,
        *_DEADLINE_ALERT_SCHEMA,
    ],
    46: ["ALTER TABLE goals ADD COLUMN connection_selection TEXT NOT NULL DEFAULT ''"],
    45: _HISTORY_INDEXES,
    44: _PERSONAL_ALERT_MIGRATION,
    43: ["ALTER TABLE facts ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'"],
    42: [_GOAL_MUTATION_SCHEMA],
    40: [statement for statement in _EVENT_ADMISSION_SCHEMA.split(";") if statement.strip()],
    41: [
        "ALTER TABLE event_goal_admissions ADD COLUMN request_digest TEXT",
        "ALTER TABLE event_goal_admissions ADD COLUMN sealed_contract TEXT",
        "CREATE INDEX IF NOT EXISTS idx_event_admission_goal ON event_goal_admissions(goal_id)",
    ],
    # v11: per-goal owner principal for multi-user dashboard authz (owner-scoped
    # reads/mutations). Legacy goals get '' (treated as unowned -> admin-only).
    11: ["ALTER TABLE goals ADD COLUMN owner TEXT NOT NULL DEFAULT ''"],
    2: [
        "ALTER TABLE episodes ADD COLUMN cost_dollars REAL DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN input_tokens INTEGER DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN output_tokens INTEGER DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN tool_calls INTEGER DEFAULT 0",
    ],
    3: [],  # goal_events table is in SCHEMA (idempotent CREATE)
    4: [],  # conversations/turns tables are in SCHEMA (idempotent CREATE)
    5: [],  # attachments table is in SCHEMA (idempotent CREATE)
    6: [],  # processed_messages table is in SCHEMA (idempotent CREATE)
    # episodes.ended_at + goal_events.ts indexes.
    # list_episodes() does `ORDER BY ended_at DESC LIMIT N` which is a
    # full table scan without the index once a workspace holds thousands
    # of episodes (a large evaluation sweep easily does), which slows the
    # dashboard's recent-episodes query. prune_goal_events queries by
    # ts < cutoff.
    7: [
        "CREATE INDEX IF NOT EXISTS idx_episodes_ended_at "
        "ON episodes(ended_at)",
        "CREATE INDEX IF NOT EXISTS idx_goal_events_ts "
        "ON goal_events(ts)",
    ],
    # Schema v8: hot-query indexes identified via EXPLAIN QUERY PLAN.
    #
    # - list_episodes(goal_id=...) filters by goal_id then orders by
    #   started_at: needs idx_episodes_goal_started.
    # - list_episodes() (no goal filter) orders by started_at: full
    #   table scan was OK on small DBs, painful at 100k+ episodes.
    # - monitor.snapshot resolves the active goal by status + ORDER BY
    #   updated_at DESC LIMIT 1: covers via idx_goals_status_updated.
    # - cross_goal_memory.recall scans WHERE status IN (succeeded,
    #   done, failed) ORDER BY updated_at DESC LIMIT 500: covered by
    #   idx_goals_status_updated.
    # - parent_id filter for _fetch_subgoals: needs idx_goals_parent.
    8: [
        "CREATE INDEX IF NOT EXISTS idx_episodes_goal_started "
        "ON episodes(goal_id, started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_episodes_started "
        "ON episodes(started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_goals_status_updated "
        "ON goals(status, updated_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_goals_parent "
        "ON goals(parent_id, created_at)",
    ],
    # v9 approval queue: the approvals table + its status index are in
    # SCHEMA (idempotent CREATE). Listed here so existing DBs bump the
    # version and pick them up on next open, matching the goal_events /
    # conversations / attachments migration pattern above.
    9: [],
    # v10: backfill the messages_fts index. The FTS table + its triggers only
    # index FUTURE writes, so a DB whose messages predate the index (created
    # before messages_fts shipped) carried unindexed history that
    # search_messages() silently missed. Rebuild once on upgrade -- a cheap
    # no-op on a DB that's already fully indexed.
    10: ["INSERT INTO messages_fts(messages_fts) VALUES('rebuild')"],
    # v12: trusted approval provenance. Do not infer operator-visible source
    # labels from the free-form detail text, which can contain model-, user-,
    # or remote-server-controlled content.
    12: ["ALTER TABLE approvals ADD COLUMN provenance TEXT"],
    # v13 collaborative supervision: approval claiming (so two supervisors
    # don't double-handle the same pending approval) + decided_by attribution.
    13: [
        "ALTER TABLE approvals ADD COLUMN claimed_by TEXT",
        "ALTER TABLE approvals ADD COLUMN claimed_at REAL",
        "ALTER TABLE approvals ADD COLUMN decided_by TEXT",
    ],
    # v14 department attribution: the domain pack a goal ran as ('' = generic
    # orchestrator). Exact success-side attribution for the learning loops
    # (dreaming, role stats, budget priors) instead of lexical matching.
    14: ["ALTER TABLE goals ADD COLUMN domain TEXT NOT NULL DEFAULT ''"],
    # v15 automation provenance: the goal_origins table (which schedule/trigger
    # spawned a goal) is in SCHEMA (idempotent CREATE). Listed here so existing
    # DBs bump the version and pick it up on next open, matching the v9 pattern.
    15: [],
    # v16 deliverable sign-off: the signoffs table is in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version on next open.
    16: [],
    # v17 governed/temporal memory: provenance + trust tier on the live fact row
    # (Memory Guard), and the bitemporal fact_history table + its index (in SCHEMA
    # as idempotent CREATE) for non-destructive fact evolution. The ALTERs add the
    # provenance columns to existing DBs; legacy facts backfill to trust_tier=3
    # (first-party) so the guard never retroactively hides already-trusted memory.
    17: [
        "ALTER TABLE facts ADD COLUMN source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE facts ADD COLUMN trust_tier INTEGER NOT NULL DEFAULT 3",
        "ALTER TABLE facts ADD COLUMN sensitivity TEXT NOT NULL DEFAULT 'internal'",
    ],
    # v18 artifacts: the artifacts table + its index are in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version on next open.
    18: [],
    # v19 projects ("matters"): the projects table is in SCHEMA (idempotent
    # CREATE); the ALTER adds the goals.project_id column to pre-existing DBs
    # (legacy goals default to NULL = unfiled). No index -- project filtering
    # scans like the owner/domain filters; goal counts are small.
    19: [
        "ALTER TABLE goals ADD COLUMN project_id INTEGER",
    ],
    # v20 share links: the share_links table is in SCHEMA (idempotent CREATE);
    # listed here so existing DBs bump the version on next open.
    20: [],
    # v21 N-of-M dual control: quorum + requester columns on approvals, and the
    # per-(approval, approver) signoff table (also in SCHEMA for fresh DBs).
    21: [
        "ALTER TABLE approvals ADD COLUMN approvals_required INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE approvals ADD COLUMN requested_by TEXT",
        "CREATE TABLE IF NOT EXISTS approval_signoffs ("
        " approval_id INTEGER NOT NULL, approver TEXT NOT NULL,"
        " decision TEXT NOT NULL, decided_at REAL NOT NULL, note TEXT,"
        " PRIMARY KEY (approval_id, approver))",
    ],
    # v22 cluster-wide killswitch: the halt table is in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version on next open.
    22: [],
    # v23 cluster-wide provider spend ledger: the provider_spend table is in
    # SCHEMA (idempotent CREATE); listed here so existing DBs bump the version.
    23: [],
    # v24 facts provenance columns (source/trust_tier/sensitivity): SQLite's base
    # CREATE and the v17 migration already carry these, so this is empty -- it
    # exists only to keep the SQLite head at v24 to match the Postgres ladder
    # (which adds the columns at v24). See migration_governance head-parity gate.
    24: [],
    # v25 fleet learning store: the harness_* tables are in SCHEMA (idempotent
    # CREATE, applied on every open); listed here so existing DBs bump the
    # version, matching the v9/v15/v22 pattern and the Postgres ladder.
    25: [],
    # v26 fleet learning store eval corpus: harness_corpus is in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version.
    26: [],
    # v27 cache-token spend columns: Budget breaks out cache_read/cache_write
    # tokens (priced at 0.1x / 1.25-2x) but the episode row dropped them, so
    # nothing persisted could answer "how much of this goal's input was cache
    # vs fresh" — the tokens-per-goal efficiency baseline needs both buckets.
    27: [
        "ALTER TABLE episodes ADD COLUMN cache_read_tokens INTEGER DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN cache_write_tokens INTEGER DEFAULT 0",
    ],
    # v28 Postgres adds goals.owner for SQLite owner-scoped episode parity.
    # SQLite has carried this column since v11, so its matching head is a no-op.
    28: [],
    # v29 immutable, privacy-minimized erasure receipts. The signed manifest
    # contains random receipt identity plus exact pre-delete row IDs, but no
    # channel/user value or subject-derived hash. A trigger prevents updates;
    # rows may only be inserted or retired after their signed retention date.
    29: [
        "CREATE TABLE IF NOT EXISTS erasure_receipts ("
        " receipt_id TEXT PRIMARY KEY,"
        " tenant_id TEXT NOT NULL,"
        " manifest TEXT NOT NULL,"
        " created_at REAL NOT NULL,"
        " retained_until REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_erasure_receipts_retention "
        "ON erasure_receipts(retained_until)",
        "CREATE TRIGGER IF NOT EXISTS erasure_receipts_no_update "
        "BEFORE UPDATE ON erasure_receipts BEGIN "
        "SELECT RAISE(ABORT, 'erasure receipts are immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS erasure_receipts_no_early_delete "
        "BEFORE DELETE ON erasure_receipts "
        "WHEN OLD.retained_until > CAST(strftime('%s', 'now') AS REAL) BEGIN "
        "SELECT RAISE(ABORT, 'erasure receipt retention is active'); END",
    ],
    # v30 approval/audit atomicity: a dashboard vote and its stable audit
    # delivery intent commit together.  The approval remains pending until
    # every queued vote is durably appended to the signed audit chain.
    30: [
        "CREATE TABLE IF NOT EXISTS approval_audit_outbox ("
        " event_id TEXT PRIMARY KEY,"
        " approval_id INTEGER NOT NULL,"
        " status TEXT NOT NULL,"
        " decided_by TEXT NOT NULL,"
        " final_status TEXT,"
        " created_at REAL NOT NULL,"
        " delivered_at REAL)",
        "CREATE INDEX IF NOT EXISTS idx_approval_audit_outbox_pending "
        "ON approval_audit_outbox(delivered_at, approval_id)",
    ],
    # v31 Postgres introduces a dedicated BIGSERIAL fact write clock. SQLite's
    # INTEGER PRIMARY KEY ``facts.id`` already serves as its 64-bit logical
    # write clock and advances on every upsert, so its matching migration is a
    # no-op that keeps the governed backend ladders at the same release head.
    31: [],
    # v32 separates human/resource ownership from execution authority. This
    # lets delegated fleet work remain owner-visible while the exact runtime
    # capability principal is still durably bound before execution.
    32: [
        "ALTER TABLE goals ADD COLUMN execution_principal "
        "TEXT NOT NULL DEFAULT ''",
    ],
    # v33 HALT generation: a clear is a compare-and-delete against the exact
    # shared stop it observed.  A concurrent arm publishes a fresh random token
    # and therefore cannot be erased by an older clear request.
    33: [
        "ALTER TABLE halt ADD COLUMN generation TEXT NOT NULL DEFAULT ''",
    ],
    # v34 durable provider admission receipts share the spend transaction.
    34: [
        "CREATE TABLE IF NOT EXISTS provider_cap_receipts ("
        " period_key TEXT NOT NULL, provider TEXT NOT NULL,"
        " receipts_json TEXT NOT NULL, PRIMARY KEY (period_key, provider))",
    ],
    # v35 prevents crash/replay from admitting the same physical provider
    # operation attempt through another provider or accounting period.
    35: [
        "CREATE TABLE IF NOT EXISTS provider_operation_attempts ("
        " scope_sha256 TEXT NOT NULL, operation_id TEXT NOT NULL,"
        " attempt_no INTEGER NOT NULL, category TEXT NOT NULL,"
        " parent_category TEXT NOT NULL, service TEXT, provider TEXT NOT NULL,"
        " period_key TEXT NOT NULL, request_id TEXT NOT NULL,"
        " PRIMARY KEY (scope_sha256, operation_id, attempt_no),"
        " UNIQUE (provider, period_key, request_id))",
        "CREATE TABLE IF NOT EXISTS provider_operation_attempt_backfill ("
        " singleton INTEGER PRIMARY KEY CHECK(singleton = 1),"
        " completed INTEGER NOT NULL CHECK(completed = 1))",
    ],
    # v36: recorded completion time and exact approval routing. Legacy rows
    # remain unknown instead of fabricating historical SLA/department data.
    36: [
        "ALTER TABLE goals ADD COLUMN completed_at REAL",
        "ALTER TABLE approvals ADD COLUMN goal_id INTEGER",
        "ALTER TABLE approvals ADD COLUMN department TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_goals_domain_completed ON goals(domain, completed_at)",
    ],
    37: [
        "CREATE INDEX IF NOT EXISTS idx_goals_root_owner ON goals(owner, id DESC) WHERE parent_id IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_goals_root_id ON goals(id DESC) WHERE parent_id IS NULL",
    ],
    38: [_ATTACHMENT_SUBMISSION_SCHEMA],
    # PostgreSQL v39 scopes learning keys by tenant; SQLite files already do.
    39: [],
}


def _approval_audit_event_id(
    tenant_id: str | None,
    approval_id: int,
    status: str,
    decided_by: str,
    undo_round: int = 0,
) -> str:
    """Stable, unambiguous id for retrying one supervisor's exact vote.

    ``undo_round`` counts how many times the approval was undone: a vote
    cast after an undo is a new decision and gets a new identity, so the
    signed audit chain records it instead of treating it as a replay of the
    retracted vote. Round 0 keeps the historical id.
    """
    parts = [
        (tenant_id or "").encode("utf-8"),
        str(int(approval_id)).encode("ascii"),
        status.encode("ascii"),
        decided_by.encode("utf-8"),
    ]
    if int(undo_round) > 0:
        parts.append(f"undo-round:{int(undo_round)}".encode("ascii"))
    framed = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    return "approval-v1-" + hashlib.sha256(framed).hexdigest()


APPROVAL_UNDO_STATUS = "undone"
# ``approvals.undo_hold``: a waiting task holds the decision for undo, or has acted on it.
APPROVAL_UNDO_OPEN = "open"


def approval_held_open(approval: Any) -> bool:
    """A request a waiting task holds open for undo (not yet settled)."""
    return getattr(approval, "undo_hold", None) == APPROVAL_UNDO_OPEN


_EPISODE_SPEND_COLS = (
    "e.id, e.goal_id, e.started_at, e.ended_at, e.outcome, "
    "COALESCE(e.cost_dollars, 0) AS cost_dollars, "
    "COALESCE(e.input_tokens, 0) AS input_tokens, "
    "COALESCE(e.output_tokens, 0) AS output_tokens, "
    "COALESCE(e.tool_calls, 0) AS tool_calls, "
    "COALESCE(e.cache_read_tokens, 0) AS cache_read_tokens, "
    "COALESCE(e.cache_write_tokens, 0) AS cache_write_tokens "
)


def _temporal_memory_enabled() -> bool:
    """Whether to keep a bitemporal ``fact_history`` (validity windows) on every
    fact change. OFF by default -- the live-value path is byte-identical when off
    (upsert overwrites, no history rows). Turn on with ``MAVERICK_TEMPORAL_MEMORY=1``
    or ``[memory] temporal = true`` for non-destructive fact evolution and
    ``get_fact(..., as_of=...)`` / ``fact_history(...)`` queries."""
    if (os.environ.get("MAVERICK_TEMPORAL_MEMORY") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return True
    try:
        from .config import load_config
        return bool(load_config().get("memory", {}).get("temporal", False))
    except Exception:  # pragma: no cover -- config never blocks a write
        return False


def _enc_field(text: str | None, context: str | None = None, *,
               bind_tenant: bool = False) -> str | None:
    """Seal a sensitive text field for storage when at-rest encryption is on.

    ``context`` names the destination column (``"goals.title"``): the value is
    then bound to that column (GCM associated data), so a ciphertext moved to
    another cell fails to open there instead of decrypting. ``bind_tenant``
    adds the current tenant to the binding: the Postgres backend sets it,
    because every tenant's rows share its tables; a SQLite world is one file
    per tenant and is read from whatever request context opens it. Without a
    context the legacy unbound token is written.

    Fail-closed: if encryption is enabled but the crypto backend is missing,
    this raises (via ``seal_to_str``) rather than silently storing plaintext.
    Returns the value unchanged when encryption is off (and for ``None``)."""
    if text is None:
        return text
    from .crypto_at_rest import at_rest_enabled, seal_bound_to_str, seal_to_str
    if not at_rest_enabled():
        return text
    if not context:
        return seal_to_str(text)
    return seal_bound_to_str(text, context, bind_tenant=bind_tenant)


# Stores whose on-disk marker says `maverick encryption migrate` left no
# plaintext behind, and stores opened without one. Strict reads switch on by
# themselves only when every store this process opened is migrated: a mixed
# process keeps the lenient default so an unmigrated tenant stays readable.
_MIGRATED_STORES: set[str] = set()
_LEGACY_STORES: set[str] = set()
_POSTGRES_STORE_POSTURES: dict[tuple[str, str | None], bool] = {}
_MIGRATED_MARKER_SUFFIX = ".at-rest-migrated.json"


def migrated_marker_path(db_path) -> Path:
    """Where ``maverick encryption migrate`` records that ``db_path`` is fully
    sealed (next to the DB, so a copied or restored store carries its posture)."""
    db_path = Path(db_path)
    return db_path.with_name(db_path.name + _MIGRATED_MARKER_SUFFIX)


def _note_store_posture(db_path) -> None:
    try:
        key = str(Path(db_path).resolve())
    except OSError:
        return
    if migrated_marker_path(db_path).exists():
        _MIGRATED_STORES.add(key)
        _LEGACY_STORES.discard(key)
    else:
        _LEGACY_STORES.add(key)
        _MIGRATED_STORES.discard(key)


def auto_strict_at_rest() -> bool:
    """True when every world store this process opened carries the migration
    marker, so an unsealed value in a sealed column can only be tampering.
    Postgres markers apply only to the active tenant."""
    if not _POSTGRES_STORE_POSTURES:
        return bool(_MIGRATED_STORES) and not _LEGACY_STORES
    from .paths import current_tenant_strict

    tenant = current_tenant_strict()
    postgres = [bound for (_, owner), bound in _POSTGRES_STORE_POSTURES.copy().items()
                if owner == tenant]
    return bool(_MIGRATED_STORES or postgres) and not _LEGACY_STORES and all(postgres)


def _strict_reads() -> bool:
    from .crypto_at_rest import strict_at_rest
    return strict_at_rest() or auto_strict_at_rest()


# Backends without a verified rebinding posture can opt out of treating legacy
# unbound values as tampering. Postgres now reports its per-tenant database
# marker through _POSTGRES_STORE_POSTURES instead of opting out wholesale.
_UNREBOUND_BACKENDS: set[str] = set()


def _unbound_is_tampering() -> bool:
    """True when every store this process reads was rebound by ``maverick
    encryption migrate`` (the marker records it), so a sealed column can only
    hold a value bound to that column. An unbound sealed value there was copied
    in from somewhere else: the corpus, a webhook secret, a sealed file."""
    return auto_strict_at_rest() and not _UNREBOUND_BACKENDS


# Returned in strict mode when a sealed column holds an unsealed value (legacy
# plaintext that wasn't migrated, or tampering) -- never the real plaintext.
_UNSEALED_WITHHELD = "‹withheld: unsealed value in an encrypted store›"
# One unreadable value was logged at ERROR on every read: the navigation bell
# polls, so a single bad row filled the log (1,198 lines in one day). Each
# distinct cause is an ERROR once per process; repeats are DEBUG.
_WITHHELD_LOGGED: set[str] = set()
_WITHHELD_LOGGED_MAX = 256


def _log_withheld_once(exc: Exception) -> None:
    cause = str(exc)
    if cause in _WITHHELD_LOGGED:
        log.debug("at-rest: withholding a bound value that fails authentication (%s)", cause)
        return
    if len(_WITHHELD_LOGGED) < _WITHHELD_LOGGED_MAX:
        _WITHHELD_LOGGED.add(cause)
    log.error("at-rest: withholding a bound value that fails authentication "
              "(%s); repeats of this cause are logged at debug level", cause)


def _dec_field(text: str | None, *, at_rest: bool | None = None,
               context: str | None = None,
               key_cache: dict[tuple[str, bytes], object] | None = None) -> str | None:
    """Unseal a stored field from a sealed column when at-rest encryption is on.

    ``context`` is the column being read (``"goals.title"``). A bound token
    that says it belongs elsewhere is withheld as an integrity failure: a
    value moved between cells never decrypts in its new place. Without a
    context the token's own (authenticated) context opens it. Once every store
    is migrated, an unbound token read from a named column is withheld too
    (see :func:`_unbound_is_tampering`).

    ``at_rest`` lets a caller that already resolved :func:`at_rest_enabled`
    for a whole result set pass it down: the policy check walks the compliance
    profile configuration each time (~90 us), and a 200-row page read it 400
    times.

    When encryption is disabled, fields are raw plaintext (which may legitimately
    begin with the public seal marker), so they pass through untouched.

    When encryption is on but the stored value is NOT sealed, it is either
    pre-migration legacy plaintext or tampering. By default it is passed through
    (so a not-yet-migrated store stays readable) with a warning; under
    :func:`strict_at_rest` it is withheld and logged as an integrity failure --
    closing the read-side plaintext-passthrough hole.
    """
    if text is None:
        return text
    from .crypto_at_rest import (
        EncryptionUnavailable,
        at_rest_enabled,
        bound_str_context,
        is_sealed_str,
        unseal_from_str,
    )
    if at_rest is None:
        at_rest = at_rest_enabled()
    if not at_rest:
        return text
    if context is not None:
        embedded = bound_str_context(text)
        if embedded is not None and embedded != context:
            log.error("at-rest: withholding a sealed value bound to %s read from %s "
                      "(moved between columns)", embedded, context)
            return _UNSEALED_WITHHELD
        if embedded is None and is_sealed_str(text) and _unbound_is_tampering():
            log.error("at-rest: withholding an unbound sealed value read from %s "
                      "(a migrated store holds only column-bound values)", context)
            return _UNSEALED_WITHHELD
    if is_sealed_str(text):
        try:
            return unseal_from_str(text) if key_cache is None else unseal_from_str(text, key_cache=key_cache)
        except EncryptionUnavailable as exc:
            if bound_str_context(text) is None:
                raise
            _log_withheld_once(exc)
            return _UNSEALED_WITHHELD
    if _strict_reads():
        log.error("at-rest strict: withholding an unsealed value in a sealed column "
                  "(run 'maverick encryption migrate'; tampering if already migrated)")
        return _UNSEALED_WITHHELD
    log.warning("at-rest: unsealed value in a sealed column (pre-migration legacy or "
                "tampering); run 'maverick encryption migrate'")
    return text


def _dec_field_or_withheld(text: str | None) -> str | None:
    from .crypto_at_rest import EncryptionUnavailable

    try:
        return _dec_field(text)
    except EncryptionUnavailable as exc:
        log.error("at-rest: withholding a value in a result set that cannot be "
                  "opened (%s)", exc)
        return _UNSEALED_WITHHELD


def _dec_fields(texts: list[str | None],
                contexts: str | list[str | None] | None = None) -> list[str | None]:
    """Decrypt a result set with one policy and key lookup per query.

    ``contexts`` is the column every value came from, or one column per
    value; a bound token read from the wrong column is withheld (see
    :func:`_dec_field`)."""
    from .crypto_at_rest import (
        EncryptionUnavailable,
        at_rest_enabled,
        bound_str_context,
        is_sealed_str,
        unseal_many_from_str,
    )

    if not at_rest_enabled():
        return list(texts)
    if isinstance(contexts, str) or contexts is None:
        expected: list[str | None] = [contexts] * len(texts)
    else:
        expected = list(contexts)
        if len(expected) != len(texts):
            raise ValueError("one context per value")
    present = [text for text in texts if text is not None]
    try:
        decoded_present = unseal_many_from_str(present)
    except EncryptionUnavailable:
        # One bad token must not hide the page: fall back to per-value reads,
        # withholding a value that cannot be opened (an unbound legacy token
        # makes _dec_field raise, which would fail the whole list read).
        decoded_present = [_dec_field_or_withheld(text) for text in present]
    strict = (
        _strict_reads()
        if any(not is_sealed_str(text) for text in present)
        else False
    )
    decoded_iter = iter(decoded_present)
    out: list[str | None] = []
    for text, want in zip(texts, expected, strict=True):
        if text is None:
            out.append(None)
            continue
        decoded = next(decoded_iter)
        if want is not None:
            embedded = bound_str_context(text)
            if embedded is not None and embedded != want:
                log.error("at-rest: withholding a sealed value bound to %s read from %s "
                          "(moved between columns)", embedded, want)
                out.append(_UNSEALED_WITHHELD)
                continue
            if embedded is None and is_sealed_str(text) and _unbound_is_tampering():
                log.error("at-rest: withholding an unbound sealed value read from %s "
                          "(a migrated store holds only column-bound values)", want)
                out.append(_UNSEALED_WITHHELD)
                continue
        if not is_sealed_str(text):
            if strict:
                log.error(
                    "at-rest strict: withholding an unsealed value in a sealed "
                    "column (run 'maverick encryption migrate'; tampering if "
                    "already migrated)"
                )
                decoded = _UNSEALED_WITHHELD
            else:
                log.warning(
                    "at-rest: unsealed value in a sealed column (pre-migration "
                    "legacy or tampering); run 'maverick encryption migrate'"
                )
        out.append(decoded)
    return out


def _row_for(cls, d: dict) -> dict:
    """Keep only the keys that ``cls`` (a dataclass) declares.

    A live ``world.db`` can carry columns written by a different schema
    version -- e.g. a build that added a ``domain`` column to ``goals``.
    ``cls(**dict(row))`` would then raise ``TypeError`` on that unknown column
    and 500 every page that lists the table. Dropping unmodelled columns keeps
    reads tolerant of schema skew in both directions.
    """
    allowed = {f.name for f in fields(cls)}
    return {k: v for k, v in d.items() if k in allowed}


def _goals_from_rows(rows) -> list[Goal]:
    """Build Goals from a result set with one at-rest policy and key lookup
    per query (rather than loading the key again for each sealed field)."""
    records = [dict(row) for row in rows]
    texts: list[str | None] = []
    contexts: list[str | None] = []
    for d in records:
        texts += [d.get("title"), d.get("description")]
        contexts += ["goals.title", "goals.description"]
        if "result" in d:
            texts.append(d["result"])
            contexts.append("goals.result")
    decoded = iter(_dec_fields(texts, contexts))
    for d in records:
        d["title"] = next(decoded)
        d["description"] = next(decoded)
        if "result" in d:
            d["result"] = next(decoded)
    return [Goal(**_row_for(Goal, d)) for d in records]


def _episode_spends_from_rows(rows: list) -> list[EpisodeSpend]:
    """Build run-cost episodes, decrypting the sealed outcome field, while
    resolving encryption policy and keys once."""
    records = [dict(row) for row in rows]
    decoded = iter(_dec_fields([d.get("outcome") for d in records if "outcome" in d],
                               "episodes.outcome"))
    for d in records:
        if "outcome" in d:
            d["outcome"] = next(decoded)
    return [EpisodeSpend(**_row_for(EpisodeSpend, d)) for d in records]


def _notify_approval_created(world, approval_id: int, provenance: str | None) -> None:
    """Best-effort chat notification (Slack and Teams approval cards); never
    raises. Called once, after the approval row is committed."""
    try:
        from .approval_notify import approval_created

        approval_created(int(approval_id), provenance=provenance, world=world)
    except Exception:  # noqa: BLE001 -- the queue row is already durable
        logging.getLogger(__name__).warning("approval notification failed", exc_info=True)


def _notify_approval_decided(world, approval_id: int) -> None:
    """Best-effort Teams card update once a decision has taken effect; never
    raises. Called after the decision is committed."""
    try:
        from .approval_notify import approval_decided

        approval_decided(int(approval_id), world=world)
    except Exception:  # noqa: BLE001 -- the decision is already durable
        logging.getLogger(__name__).warning("approval decision notification failed", exc_info=True)


def _approval_from_row(row, *, at_rest=None, key_cache=None) -> Approval:
    """Build an Approval from a row, decrypting the sealed action/scope/detail."""
    d = dict(row)
    for field in ("action", "scope", "detail"):
        d[field] = _dec_field(d.get(field), context=f"approvals.{field}",
                              at_rest=at_rest, key_cache=key_cache)
    return Approval(**_row_for(Approval, d))


def _approvals_from_rows(rows: list) -> list[Approval]:
    """Build approvals while resolving encryption policy and keys once.

    Decoding each row on its own checked the policy (the compliance profile
    configuration) and loaded the key for every sealed field: listing 500
    approvals took 250-450 ms.
    """
    sealed = ("action", "scope", "detail")
    records = [dict(row) for row in rows]
    decoded = iter(_dec_fields([d.get(name) for d in records for name in sealed],
                               [f"approvals.{name}" for _d in records for name in sealed]))
    for d in records:
        for name in sealed:
            d[name] = next(decoded)
    return [Approval(**_row_for(Approval, d)) for d in records]


def _single_approver(approval, approvers: list[str]) -> list[str]:
    """A one-approver request keeps no sign-off rows: its approver is the decider."""
    if (
        not approvers
        and approval.status == "approved"
        and max(1, int(approval.approvals_required or 1)) <= 1
        and approval.decided_by
    ):
        return [approval.decided_by]
    return approvers


def _same_person(a: object, b: object) -> bool:
    from .safety.dual_control import person_key

    return bool(person_key(a)) and person_key(a) == person_key(b)


def _people(rows) -> int:
    """Distinct people among approver rows (one person spelt two ways is one)."""
    from .safety.dual_control import distinct_people

    return distinct_people(row[0] for row in rows)


def _approval_state_view(approval, approvers: list[str], audit_pending: int) -> dict:
    """The operator/UI quorum view of one approval (shared by the per-id and
    the batched readers so both return the same shape and values)."""
    return {
        "status": approval.status,
        "approvals_required": max(1, int(approval.approvals_required or 1)),
        "approved_count": _people([a] for a in approvers),
        "approvers": approvers,
        "requested_by": approval.requested_by,
        "audit_pending_count": audit_pending,
        "effective": approval.status != "pending",
    }


def _approval_audit_event_from_row(row) -> ApprovalAuditEvent:
    return ApprovalAuditEvent(**_row_for(ApprovalAuditEvent, dict(row)))


def default_db_path() -> Path:
    """Return the active tenant's world path unless explicitly overridden.

    While practice mode is on (:mod:`maverick.practice`), the practice world
    beside it, so practised tasks never mix with real records."""
    from . import practice

    if DEFAULT_DB is not _INITIAL_DEFAULT_DB:
        override = Path(DEFAULT_DB).expanduser()
        if practice.active():
            return override.with_name(override.stem + ".practice" + override.suffix)
        return override
    tenant = current_tenant_id()
    if practice.active():
        return practice.world_path(bind_tenant_namespace(tenant) if tenant else None)
    if tenant:
        tenant = bind_tenant_namespace(tenant)
        return data_dir("world.db", tenant=tenant)
    return data_dir("world.db", tenant=None)


def _resolve_world_path(path: Path | str | None) -> tuple[Path, bool]:
    if path is None:
        # The built-in dynamic path is Second Shift-owned. A replaced DEFAULT_DB
        # is a public embedder/operator override and therefore caller-owned: it
        # must already have a private parent, never have its ACL seized.
        return default_db_path(), DEFAULT_DB is _INITIAL_DEFAULT_DB
    return Path(path), False


class WorldSchemaCompatibilityError(RuntimeError):
    """The installed release cannot safely open this persisted world."""

    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


def _existing_world_has_data(path: Path) -> bool:
    try:
        return str(path) != ":memory:" and path.exists() and path.stat().st_size > 0
    except OSError:  # pragma: no cover -- stat race; assume fresh
        return False


def _check_world_schema_compatibility(path: Path) -> None:
    """Admit existing worlds read-only, including committed WAL state.

    Called under the existing cross-process initialization lock and before
    opening a writable connection, journal-mode changes or schema bootstrap.
    Do not use immutable=1: it ignores committed versions still in a WAL.
    Missing/empty version tables retain the supported legacy-v1 reader policy.
    """
    invalid = (
        "World database schema metadata is invalid or ambiguous. "
        "Restore a compatible backup or open it with the release that created it; "
        "the database has not been migrated."
    )
    try:
        with contextlib.closing(sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0,
        )) as conn:
            table = conn.execute(
                "SELECT type FROM sqlite_master WHERE name='schema_version' COLLATE NOCASE",
            ).fetchone()
            if table is None:
                return
            if table[0] != "table":
                raise WorldSchemaCompatibilityError(invalid, code="invalid_world_schema")
            rows = conn.execute("SELECT version FROM schema_version LIMIT 2").fetchall()
    except sqlite3.DatabaseError as exc:
        raise WorldSchemaCompatibilityError(invalid, code="invalid_world_schema") from exc
    if not rows:
        return
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
        raise WorldSchemaCompatibilityError(invalid, code="invalid_world_schema")
    current = rows[0][0]
    if current > SCHEMA_VERSION:
        raise WorldSchemaCompatibilityError(
            f"World database uses schema {current}; this release supports up to {SCHEMA_VERSION}. "
            "Install a newer Second Shift release that supports this schema or restore a compatible backup; "
            "the database has not been migrated.",
            code="unsupported_world_schema",
        )


def _serialize_world_initialization(init):
    """Serialize one world's open/WAL/schema bootstrap across processes.

    SQLite's Windows VFS can surface ``SQLITE_READONLY`` when several fresh
    connections race file publication, WAL activation, and schema creation.
    Busy timeouts do not cover that state.  The durable per-world lock also
    keeps permission verification and migrations in the same admission
    transaction; it is released on every constructor exception.  In-memory
    worlds remain independent and never touch the filesystem lock.
    """
    @functools.wraps(init)
    def guarded(self, path: Path | str | None = None, *, _managed_path: bool = False):
        resolved, _ = _resolve_world_path(path)
        if str(resolved) == ":memory:":
            return init(self, path, _managed_path=_managed_path)
        with cross_process_lock(resolved, strict=True):
            return init(self, path, _managed_path=_managed_path)

    return guarded


class WorldModel:
    @_serialize_world_initialization
    def __init__(
        self,
        path: Path | str | None = None,
        *,
        _managed_path: bool = False,
    ):
        from .paths import current_tenant_id_strict
        self._event_admission_tenant = current_tenant_id_strict()
        path, default_managed = _resolve_world_path(path)
        _managed_path = _managed_path or default_managed
        self.path = path
        # Whether this DB already held data before we opened it. Captured BEFORE
        # any file creation below so a brand-new world.db (every fresh
        # install/tenant) is not mistaken for a legacy DB needing a
        # pre-migration backup -- only a pre-existing, non-empty DB gets one.
        self._db_preexisted = _existing_world_has_data(path)
        if self._db_preexisted:
            _check_world_schema_compatibility(path)
        # world.db holds all conversation content, messages, and facts.
        # The audit dir is locked to 0700/0600 but this DB inherited the
        # default umask (often world-readable 0644) — any local user or
        # backup could read everyone's data. Lock the dir + the file.
        if str(path) != ":memory:":
            _note_store_posture(path)
            # Tenant/home context is deliberately resolved at request time.
            # Treat the current managed default as Second Shift-owned and let the
            # tenant factory explicitly mark its paths.  A genuinely
            # caller-supplied parent still goes through
            # ``prepare_private_directory`` so we never seize its ACLs.
            current_default = data_dir("world.db")
            if _managed_path or path == current_default:
                ensure_private_directory(path.parent)
            else:
                prepare_private_directory(path.parent)
        # check_same_thread=False so FastAPI threadpool can share. Combined
        # with WAL + busy_timeout this is safe for the agent+dashboard
        # concurrency pattern (one writer process + many readers).
        #
        # ``check_same_thread=False`` alone
        # is insufficient. Two threadpool workers driving execute()+commit()
        # on the same connection can interleave: thread A opens an implicit
        # transaction with INSERT, thread B's INSERT joins the same
        # transaction, A's commit() flushes both rows, B's commit() is a
        # no-op. If A had raised between execute() and commit() and called
        # rollback(), B's "successful" insert would silently roll back too.
        # The RLock + ``_writing()`` context manager serialises every
        # mutation so each commit() bounds exactly one logical write.
        self._write_lock = threading.RLock()
        self._write_depth = 0
        # Goals whose stored state this transaction changed; their in-process
        # watchers (the chat page's event stream) are woken after it commits.
        self._changed_goals: set[int] = set()
        # Per-thread READ connections: WAL gives each its own connection a
        # consistent committed snapshot, so reads run concurrently with the one
        # writer instead of serialising on the write lock (WAL's many-readers
        # benefit exists only ACROSS connections). The writer thread's own reads
        # must still go through the write connection to see its uncommitted data
        # mid-transaction, tracked by _writer_ident.
        self._is_memory = str(path) == ":memory:"
        self._readers = threading.local()
        # Keyed by thread ident (not a plain list) so a dead thread's
        # connection can be pruned instead of retained for the WorldModel's
        # entire lifetime -- see _prune_dead_reader_conns_locked.
        self._reader_conns: dict[int, sqlite3.Connection] = {}
        self._reader_conns_lock = threading.Lock()
        self._writer_ident: int | None = None
        # Create the DB file 0o600 BEFORE sqlite opens it: connect() would
        # otherwise create it at the umask (often 0644) for a window before the
        # chmod below, briefly exposing all conversation content to co-tenants.
        if str(path) != ":memory:" and not path.exists():
            try:
                atomic_create_bytes(path, b"")
            except FileExistsError:
                # Another opener won the exclusive publication race.
                ensure_private_file(path)
        elif str(path) != ":memory:":
            ensure_private_file(path)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10.0)
        if str(path) != ":memory:":
            ensure_private_file(path)
        self.conn.row_factory = sqlite3.Row
        # Arm a short busy handler BEFORE switching journal mode: switching to
        # WAL needs a brief exclusive lock, and when a second connection opens
        # the same DB concurrently (the dashboard and the agent each open one)
        # the switch can surface "database is locked" instead of waiting unless
        # busy_timeout is already set. Keep this timeout small because it is
        # paid on every retry below; restore the normal write timeout after WAL
        # is enabled.
        self.conn.execute(f"PRAGMA busy_timeout = {WAL_SWITCH_BUSY_TIMEOUT_MS}")
        # WAL must be set before any other operation that creates pages. The
        # switch can still race a same-process connection -- SQLITE_LOCKED
        # bypasses the busy handler -- so retry briefly (<=5s) on a locked DB.
        deadline = time.monotonic() + WAL_SWITCH_RETRY_SECONDS
        while True:
            try:
                self.conn.execute("PRAGMA journal_mode = WAL")
                break
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower():
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
        self.conn.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS}")
        # WAL/SHM sidecars hold uncommitted conversation content; lock them to
        # 0o600 too (best-effort -- they may not exist until the first write,
        # so this is re-attempted; the 0o700 parent dir covers the gap).
        if str(path) != ":memory:":
            for _suffix in ("-wal", "-shm"):
                try:
                    ensure_private_file(path.parent / (path.name + _suffix))
                except FileNotFoundError:
                    pass
        # synchronous=NORMAL under WAL is safe (no corruption) + much faster
        # than FULL, but a commit acked to the orchestrator can still be lost on
        # an OS crash / power loss before the next checkpoint. A regulated
        # deployment that treats the world DB as the billed Operating Record can
        # opt into FULL (durable on every commit) via [world_model] synchronous
        # / MAVERICK_WORLD_SYNCHRONOUS. Default NORMAL — behaviour unchanged.
        self.conn.execute(f"PRAGMA synchronous = {_synchronous_mode()}")
        # Bound WAL file
        # growth. Default autocheckpoint=1000 pages is fine, but with
        # a dashboard reader holding a snapshot lock, autocheckpoint
        # can stall and the WAL file grows monotonically. Explicit
        # pragma surfaces the setting + makes intent clear.
        self.conn.execute("PRAGMA wal_autocheckpoint = 1000")
        # SQLite default is foreign_keys=OFF; without this, every
        # `REFERENCES goals(id)` clause is decorative and a delete can
        # orphan turns/attachments/episodes silently.
        self.conn.execute("PRAGMA foreign_keys = ON")
        # The schema-setup writes (executescript + version row + migrations) can
        # surface SQLITE_LOCKED -- not SQLITE_BUSY -- when many connections in
        # the SAME process first-open a fresh DB simultaneously; the
        # busy_timeout handler doesn't cover SQLITE_LOCKED (same reason the WAL
        # switch above needs its own retry). The version-row insert is already
        # race-safe (atomic insert-if-empty in _init_schema_version), but
        # executescript/migrations can still lose the lock race -- observed in
        # CI as an intermittent "database is locked" on concurrent first-open.
        # The whole block is idempotent (CREATE TABLE IF NOT EXISTS, the
        # empty-table version insert, re-runnable migrations), so retry it
        # briefly on a transient lock.
        deadline = time.monotonic() + WAL_SWITCH_RETRY_SECONDS
        while True:
            try:
                self.conn.executescript(_bootstrap_schema(self.conn))
                self._init_schema_version()
                self._apply_migrations()
                self.conn.commit()
                break
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower():
                    raise
                try:
                    self.conn.rollback()
                except sqlite3.Error:
                    pass
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
        # [memory] temporal is read ONCE at open, not per write: upsert_fact /
        # delete_fact are on the hot path and load_config() is uncached file
        # I/O. A config toggle takes effect on the next WorldModel open.
        self._temporal_memory = _temporal_memory_enabled()

    @contextlib.contextmanager
    def _writing(self) -> Iterator[sqlite3.Connection]:
        """Acquire the write lock, yield the connection, commit on clean exit.

        Use this around every INSERT/UPDATE/DELETE sequence. If the body
        raises, outermost scope rolls back so the next caller sees a
        consistent state. Re-entrant via RLock so methods that compose
        other mutators don't self-deadlock; nested scopes share one
        transaction and only the outermost scope commits/rolls back.
        """
        with self._write_lock:
            is_outermost = self._write_depth == 0
            if is_outermost:
                self._writer_ident = threading.get_ident()
            self._write_depth += 1
            try:
                yield self.conn
                if is_outermost:
                    self.conn.commit()
                    self._wake_changed_goals()
            except BaseException:
                # Ctrl-C or SystemExit too: an open half-applied transaction
                # would otherwise be committed by this object's next write.
                if is_outermost:
                    self.conn.rollback()
                    self.__dict__.pop("_changed_goals", None)
                raise
            finally:
                self._write_depth -= 1
                if self._write_depth == 0:
                    self._writer_ident = None

    def _goal_changed(self, goal_id: int) -> None:
        """Note, inside a write, that a watched goal's stored state changes."""
        self.__dict__.setdefault("_changed_goals", set()).add(int(goal_id))

    def _wake_changed_goals(self) -> None:
        """After the commit: wake in-process watchers. Never raises (the write
        already succeeded); a missed wake only leaves a watcher on its timer."""
        changed = self.__dict__.pop("_changed_goals", None)
        if not changed or getattr(self, "_is_memory", True):
            return
        try:
            from .goal_wakeup import notify, watching, world_key

            if not watching():
                return
            world = world_key(self.path)
            for goal_id in changed:
                notify(world, goal_id)
        except Exception:  # noqa: BLE001
            log.debug("goal wake-up skipped", exc_info=True)

    def _prune_dead_reader_conns_locked(self) -> None:
        """Close and drop reader connections whose owning thread has exited.

        Caller must hold ``_reader_conns_lock``. ``threading.local()`` itself
        already frees a dead thread's *slot*, but the strong reference kept
        here (so :meth:`close` can reclaim every connection at shutdown) would
        otherwise retain the connection -- and its WAL/SHM file descriptors --
        for the WorldModel's entire lifetime. A dashboard's WorldModel is
        process-cached for the life of the server while ASGI worker threads
        come and go (an idle anyio worker thread exits after ~10s), so an
        unpruned list grows by one leaked connection and two leaked fds per
        short-lived thread that ever reads -- a slow walk toward EMFILE.
        """
        alive = {t.ident for t in threading.enumerate()}
        for ident in [i for i in self._reader_conns if i not in alive]:
            try:
                self._reader_conns.pop(ident).close()
            except Exception:  # pragma: no cover
                pass

    def _reader(self) -> sqlite3.Connection | None:
        """A per-thread read-only connection, or ``None`` when reads must use the
        shared write connection: a ``:memory:`` DB (which is per-connection, so a
        second connection would be an empty database), or a read issued by the
        thread that currently holds an open write transaction (it must see its
        own uncommitted rows). Otherwise a WAL reader connection that sees the
        latest committed snapshot, lock-free and concurrent with the writer."""
        if self._is_memory or self._writer_ident == threading.get_ident():
            return None
        conn = getattr(self._readers, "conn", None)
        if conn is None:
            # isolation_level=None (autocommit): each SELECT is its own
            # transaction, so the reader always sees the newest commit and never
            # pins a stale snapshot or holds back a WAL checkpoint. WAL mode is a
            # persistent DB property, so a fresh connection is already in WAL.
            conn = sqlite3.connect(self.path, check_same_thread=False,
                                   timeout=10.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS}")
            self._readers.conn = conn
            with self._reader_conns_lock:
                self._prune_dead_reader_conns_locked()
                self._reader_conns[threading.get_ident()] = conn
        return conn

    def _read_all(self, sql: str, params: tuple[Any, ...] = ()) -> list:
        """Eagerly fetch all rows. Uses a per-thread WAL reader connection so
        reads run concurrently with the writer; falls back to the shared
        connection under the write lock for ``:memory:`` and writer-thread reads
        (see :meth:`_reader`)."""
        conn = self._reader()
        if conn is None:
            with self._write_lock:
                return self.conn.execute(sql, params).fetchall()
        return conn.execute(sql, params).fetchall()

    def _read_one(self, sql: str, params: tuple[Any, ...] = ()):
        """Single-row counterpart to :meth:`_read_all`."""
        conn = self._reader()
        if conn is None:
            with self._write_lock:
                return self.conn.execute(sql, params).fetchone()
        return conn.execute(sql, params).fetchone()

    def close(self) -> None:
        """Close the underlying SQLite connection.

        Benchmark runs construct ~1865
        WorldModel instances in one process; without close() the
        FD count climbs and the host eventually OOMs.

        Checkpoint + truncate
        the WAL on close so the sidecar file doesn't persist into the
        next instance's open. Best-effort; close still runs even if
        checkpoint fails.
        """
        with self._reader_conns_lock:
            readers, self._reader_conns = list(self._reader_conns.values()), {}
        for rconn in readers:
            try:
                rconn.close()
            except Exception:  # pragma: no cover
                pass
        try:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
            self.conn.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _init_schema_version(self) -> None:
        # Fast path: an already-initialized DB only needs a read. WAL readers
        # never block a concurrent writer, so don't take a write lock on every
        # open -- a second connection opening mid-write would otherwise hit
        # "database is locked".
        row = self.conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        if row is not None:
            return
        # Fresh DB: seed the single row. Concurrent first-opens raced -- the
        # old check-then-insert keyed on version=1, but a *losing* connection
        # ran its INSERT only AFTER the winner had migrated its row up to
        # SCHEMA_VERSION, so version=1 was free again and it inserted a SECOND
        # row (the try/except only caught a PK collision). Two rows then made
        # the no-WHERE `UPDATE schema_version SET version=?` in
        # _apply_migrations collide on the PK -- the intermittent fresh-open CI
        # flake. Guard on table-emptiness in one atomic statement: the WHERE
        # NOT EXISTS is re-checked under SQLite's single-writer lock, so a
        # loser that saw an empty table above still inserts nothing once the
        # winner's row is committed. At most one row, ever.
        self.conn.execute(
            "INSERT INTO schema_version(version) "
            "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version)"
        )

    def _backup_before_migration(self, from_version: int) -> None:
        """Best-effort recovery snapshot taken before applying schema migrations.

        Migrations are forward-only and irreversible; an interrupted upgrade can
        leave the world DB partially migrated with no automated rollback. Before
        the first pending migration in this open, snapshot the DB -- via SQLite's
        online-backup API, so it is consistent even under WAL -- to a sibling
        ``<db>.pre-migration-v<from>.bak`` an operator can restore from.

        Best-effort and fail-open: a snapshot failure logs and does NOT block the
        upgrade (startup must still proceed). Skipped for in-memory DBs and when
        ``[world_model] pre_migration_backup = false``.
        """
        path = getattr(self, "path", None)
        if path is None or str(path) == ":memory:":
            return
        # Only a pre-existing DB has data worth protecting; a fresh world.db
        # "migrates" v1->current on first open but has nothing to lose.
        if not getattr(self, "_db_preexisted", False):
            return
        try:
            from .config import load_config
            if load_config().get("world_model", {}).get(
                "pre_migration_backup", True
            ) is False:
                return
        except Exception:  # pragma: no cover -- config never blocks a migration
            pass
        dest = Path(f"{path}.pre-migration-v{from_version}.bak")
        if dest.exists():  # idempotent across the open-time lock-retry loop
            return
        try:
            # Quiesce the source first. executescript(SCHEMA)/_init_schema_version()
            # leave an uncommitted write transaction holding a lock on self.conn,
            # and SQLite's online backup of a connection that is mid-write-
            # transaction deadlocks (observed as a hung migration). Commit so the
            # snapshot is a clean, lock-free read of the pre-migration state; the
            # migration loop opens its own writes immediately after.
            try:
                self.conn.commit()
            except sqlite3.Error:  # pragma: no cover -- best-effort quiesce
                pass
            # Pre-create the sensitive backup with the shared create-time
            # private ACL and no-follow atomic publication before SQLite opens
            # it and writes any customer data.
            atomic_create_bytes(dest, b"")
            bdst = sqlite3.connect(str(dest))
            try:
                self.conn.backup(bdst)
            finally:
                bdst.close()  # sqlite3's context manager commits but never closes
            ensure_private_file(dest)
            log.info(
                "world: wrote pre-migration backup %s (v%s -> v%s)",
                dest, from_version, SCHEMA_VERSION,
            )
        except Exception as e:  # pragma: no cover -- snapshot is best-effort
            log.warning(
                "world: pre-migration backup failed (%s); proceeding with upgrade", e,
            )

    def _apply_migrations(self) -> None:
        current = self.conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()[0]
        # A recovery point before any forward-only migration runs.
        if current < SCHEMA_VERSION:
            self._backup_before_migration(current)
        # Temporarily bump busy_timeout for the
        # migration. CREATE INDEX on a multi-million-row table
        # (long-lived production DB) can take 30s+ and the 5s default
        # would raise "database is locked" against a running dashboard.
        # Restore after, even on exception.
        prior = None
        try:
            prior = self.conn.execute(
                "PRAGMA busy_timeout"
            ).fetchone()[0]
            self.conn.execute("PRAGMA busy_timeout = 60000")
        except sqlite3.Error:
            prior = None
        try:
            while current < SCHEMA_VERSION:
                next_version = current + 1
                # Python's sqlite3 legacy driver auto-commits DDL/
                # backfill statements one at a time outside any transaction,
                # so a failing multi-statement migration left EARLIER
                # statements of the SAME version permanently applied while
                # schema_version stayed unbumped -- an interrupted upgrade
                # left the DB in a state no later open could detect or retry
                # cleanly. Wrap each version in its own explicit transaction
                # so a failure rolls back every statement of that version.
                # `commit()` first is a safe no-op except right after a
                # fresh DB's `_init_schema_version()` INSERT, whose
                # transaction is still open here (only committed after this
                # method returns) -- BEGIN inside an open transaction raises
                # `OperationalError: cannot start a transaction within a
                # transaction`.
                self.conn.commit()
                self.conn.execute("BEGIN IMMEDIATE")
                try:
                    for stmt in MIGRATIONS.get(next_version, []):
                        try:
                            self.conn.execute(stmt)
                        except sqlite3.OperationalError as e:
                            msg = str(e).lower()
                            if "duplicate column" not in msg:
                                raise
                    self.conn.execute(
                        "UPDATE schema_version SET version = ?", (next_version,),
                    )
                    self.conn.commit()
                except BaseException:
                    self.conn.rollback()
                    raise
                current = next_version
        finally:
            if prior is not None:
                try:
                    self.conn.execute(
                        f"PRAGMA busy_timeout = {int(prior)}",
                    )
                except sqlite3.Error:
                    pass

    @property
    def schema_version(self) -> int:
        row = self.conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        return row[0] if row else 0

    # ----- goals -----
    def create_goal(self, title: str, description: str = "", parent_id: int | None = None,
                    *, owner: str = "", execution_principal: str = "",
                    domain: str = "", project_id: int | None = None,
                    connection_references: list | None = None) -> int:
        if execution_principal is None:
            execution_principal = ""
        if not isinstance(execution_principal, str):
            raise ValueError("invalid execution principal")
        if execution_principal:
            from .agent_control_plane import valid_principal

            if not valid_principal(execution_principal):
                raise ValueError("invalid execution principal")
        if connection_references:
            raise ValueError("connection references are not supported")
        selection = ""
        now = time.time()
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goals(parent_id, title, description, status, "
                "created_at, updated_at, owner, execution_principal, domain, project_id, connection_selection) "
                "VALUES(?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)",
                (parent_id, _enc_field(title, "goals.title"),
                 _enc_field(description, "goals.description"), now, now,
                 owner, execution_principal, domain or "", project_id,
                 _enc_field(selection, "goals.connection_selection")),
            )
            goal_id = cur.lastrowid
        return goal_id

    # ---- projects ("matters"): a workspace grouping related goals ----------

    # -- backend-portable raw reads ------------------------------------------
    # The dashboard's boards and exports need a handful of aggregate queries
    # that have no accessor here. Reaching into ``.conn`` directly only works
    # on SQLite (``?`` paramstyle, ``sqlite3.Row``, ``date(x, 'unixepoch')``)
    # and fails on the Postgres backend. These two
    # methods are the contract both backends implement: write the SQL in
    # SQLite paramstyle and access rows by index or by column name.

    def query(self, sql: str, params: tuple[Any, ...] | list = (), *, system: bool = False) -> list:
        """Run a read-only statement written in SQLite paramstyle (``?``) and
        return every row. Rows support both ``row[0]`` and ``row["col"]`` and
        unpack like tuples. Mirrored on the Postgres backend, which rewrites
        the paramstyle and wraps its tuple rows the same way.

        Tenant data belongs in :meth:`tenant_query`. On the shared Postgres
        store this unscoped call is refused while tenancy is on unless
        ``system=True`` marks a deliberate deployment-wide read. This file is
        already one tenant's store, so the flag changes nothing here."""
        del system
        return self._read_all(sql, tuple(params))

    def ping(self) -> bool:
        """Cheap liveness probe for ``/healthz`` -- confirms the world store
        answers a trivial read. Backend-agnostic (mirrored on Postgres) so the
        deep health check probes the SAME store the app actually uses, not a
        hard-coded local ``world.db``. Raises on failure (the caller reports it)."""
        self._read_one("SELECT 1 AS one", ())
        return True

    # ---- share links: revocable, expiring read-only access to a goal --------

    def set_goal_status(self, goal_id: int, status: str, result: str | None = None) -> None:
        # updated_at is both a timestamp and the public optimistic review
        # version. All goal timestamp writes advance it atomically in SQL:
        # coarse/repeated or backwards wall time cannot reauthorize stale
        # bytes, even when independent connections mutate the same goal.
        now = time.time()
        legacy_refused = False
        binding_scope = (execution_binding_lock(self, goal_id)
                         if status in {"active", "running"}
                         else contextlib.nullcontext(False))
        with binding_scope as binding_locked, self._writing() as conn:
            if status in {"active", "running"}:
                prior = conn.execute(
                    "SELECT g.status,g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                    "JOIN goal_origins o ON o.goal_id=g.id "
                    "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                    "WHERE g.id=? AND o.kind IN ('event','event_v2')", (int(goal_id),),
                ).fetchone()
                if prior is None and binding_locked:
                    current = conn.execute("SELECT status FROM goals WHERE id=?", (int(goal_id),)).fetchone()
                    if current is not None and current[0] not in {"active", "running"}:
                        raise EventRegistryUnavailable("Event origin disappeared during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not binding_locked):
                    raise EventRegistryUnavailable("Event binding changed during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not compatible_event_goal(prior[2], prior[3], prior[1], prior[4])):
                    legacy_refused = True
                    if prior[0] == "pending":
                        conn.execute(
                            "UPDATE goals SET status='blocked', completed_at=NULL, "
                            "updated_at=MAX(updated_at + 0.000001, ?), result=? "
                            "WHERE id=? AND status='pending'",
                            (now, _enc_field("Earlier event request held for review", "goals.result"), int(goal_id)),
                        )
                        conn.execute("DELETE FROM signoffs WHERE goal_id=?", (int(goal_id),))
            if not legacy_refused:
                cur = conn.execute(
                "UPDATE goals SET completed_at = CASE WHEN ? <> 'done' THEN NULL "
                "WHEN status = 'done' THEN completed_at "
                "ELSE MAX(updated_at + 0.000001, ?) END, "
                "status = ?, updated_at = MAX(updated_at + 0.000001, ?), "
                "result = COALESCE(?, result) WHERE id = ? "
                # A finished task stays finished: a late cancel changes nothing.
                "AND NOT (status = 'done' AND ? = 'cancelled')",
                (status, now, status, now, _enc_field(result, "goals.result"), goal_id, status),
                )
                self._goal_changed(goal_id)
            # A sign-off is authority over one immutable terminal payload, not
            # over a goal id forever.  Reruns, failures, and any result rewrite
            # revoke it atomically so old approval cannot authorize new bytes.
            if not legacy_refused and cur.rowcount == 1 and (status != "done" or result is not None):
                conn.execute("DELETE FROM signoffs WHERE goal_id = ?", (int(goal_id),))
        if legacy_refused:
            raise LegacyEventGoalHeld("Earlier event request held for review")

    def claim_goal_for_run(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Atomically claim one pending goal for execution.

        Remote dispatch is an at-least-once boundary: a worker RPC can be
        repeated after a timeout or a lost response.  The status transition is
        therefore the execution claim, not a preceding read.  Exactly one
        contender can move ``pending`` to ``active``; later calls observe the
        already-active or terminal row and must not execute it again.

        ``expected_owner`` is included in the same compare-and-swap so the
        authorization check cannot be separated from the state change by a
        race.  ``None`` is the administrative scope and intentionally omits the
        owner predicate.
        """
        sql = (
            "UPDATE goals SET status = 'active', updated_at = MAX(updated_at + 0.000001, ?) "
            "WHERE id = ? AND status = 'pending'"
        )
        params: tuple[Any, ...] = (time.time(), int(goal_id))
        if expected_owner is not None:
            sql += " AND owner = ?"
            params += (str(expected_owner),)
        with execution_binding_lock(self, goal_id) as binding_locked, self._writing() as conn:
            owner_clause = " AND g.owner=?" if expected_owner is not None else ""
            legacy = conn.execute(
                "SELECT g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                "JOIN goal_origins o ON o.goal_id=g.id "
                "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                "WHERE g.id=? AND g.status='pending' "
                "AND o.kind IN ('event','event_v2')" + owner_clause,
                (int(goal_id), *((str(expected_owner),) if expected_owner is not None else ())),
            ).fetchone()
            if legacy is None and binding_locked:
                eligible = conn.execute(
                    "SELECT 1 FROM goals WHERE id=? AND status='pending'" +
                    (" AND owner=?" if expected_owner is not None else ""),
                    (int(goal_id), *((str(expected_owner),) if expected_owner is not None else ())),
                ).fetchone()
                if eligible is not None:
                    raise EventRegistryUnavailable("Event origin disappeared during execution claim")
            if legacy is not None and not binding_locked:
                raise EventRegistryUnavailable("Event binding changed during execution claim")
            if legacy is not None and not compatible_event_goal(
                    legacy[1], legacy[2], legacy[0], legacy[3]):
                conn.execute(
                    "UPDATE goals SET status='blocked', completed_at=NULL, "
                    "updated_at=MAX(updated_at + 0.000001, ?), result=? "
                    "WHERE id=? AND status='pending'",
                    (time.time(), _enc_field("Earlier event request held for review", "goals.result"),
                     int(goal_id)),
                )
                conn.execute("DELETE FROM signoffs WHERE goal_id=?", (int(goal_id),))
                return False
            cur = conn.execute(sql, params)
            return cur.rowcount == 1

    def touch_goal(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Refresh a live goal's ``heartbeat_at`` — the orphan-reclaim liveness
        signal — without any other side effect. ``updated_at`` stays put: it
        is the version a reviewed Stop or edit binds to, and a heartbeat is
        not a change the reviewer needs to see again.

        A pure keep-alive for work running OUTSIDE this process (external
        agents heartbeating a run, remote workers between status writes):
        ``set_goal_status('active')`` would drop signoffs and flip a pending
        row, so liveness gets its own single-statement primitive. Only
        in-flight rows qualify; terminal goals are never revived. The owner
        predicate rides in the same statement so authorization cannot be
        separated from the touch by a race."""
        sql = ("UPDATE goals SET heartbeat_at = MAX(COALESCE(heartbeat_at, 0), ?) "
               "WHERE id = ? AND status IN ('active', 'pending')")
        params: tuple[Any, ...] = (time.time(), int(goal_id))
        if expected_owner is not None:
            sql += " AND owner = ?"
            params += (str(expected_owner),)
        with self._writing() as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount == 1

    def get_goal(self, goal_id: int) -> Goal | None:
        row = self._read_one("SELECT * FROM goals WHERE id = ?", (goal_id,))
        # One at-rest policy and key lookup for the row's sealed fields.
        return _goals_from_rows([row])[0] if row else None

    def list_goals(
        self,
        status: str | None = None,
        *,
        owner: str | None = None,
        domain: str | None = None,
        project_id: int | None = None,
        limit: int | None = None,
        offset: int = 0,
        order: str = "asc",
        before_id: int | None = None,
        strict_tenant: bool = False,
    ) -> list[Goal]:
        """List goals, optionally filtered + paginated.

        Defaults preserve historical behaviour (``limit=None`` returns
        all rows in ASC id order). Dashboard callers should pass a
        small ``limit`` to avoid loading every goal on every request;
        ``order='desc'`` lets the most-recent slice be fetched cheaply.
        ``domain`` scopes to one department (the pack a goal ran as) -- the
        ``domain`` column is plaintext, so it filters in SQL.
        ``before_id`` excludes that immutable ID and all newer IDs without
        reading an anchor row. Use descending order for continuation; in
        ascending order it remains only an upper ID bound. Existing offset
        callers retain their historical behavior. ``strict_tenant`` is accepted
        for backend parity; SQLite databases are already tenant-scoped.
        """
        if before_id is not None and not 0 < int(before_id) <= 2**63 - 1:
            raise ValueError("before_id must be a positive signed 64-bit goal ID")
        direction = "DESC" if order.lower() == "desc" else "ASC"
        sql = "SELECT * FROM goals"
        clauses: list[str] = []
        params: tuple[Any, ...] = ()
        if status:
            clauses.append("status = ?")
            params = params + (status,)
        if owner is not None:
            clauses.append("owner = ?")
            params = params + (owner,)
        if domain is not None:
            clauses.append("domain = ?")
            params = params + (domain,)
        if project_id is not None:
            clauses.append("project_id = ?")
            params = params + (int(project_id),)
        if before_id is not None:
            clauses.append("id < ?")
            params = params + (int(before_id),)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += f" ORDER BY id {direction}"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = params + (max(1, int(limit)), max(0, int(offset)))
        rows = self._read_all(sql, params)
        return _goals_from_rows(rows)

    # ----- episodes -----
    def start_episode(self, goal_id: int) -> int:
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO episodes(goal_id, started_at) VALUES(?, ?)",
                (goal_id, time.time()),
            )
            return cur.lastrowid

    def end_episode(
        self,
        episode_id: int,
        summary: str,
        outcome: str,
        cost_dollars: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        with self._writing() as conn:
            conn.execute(
                "UPDATE episodes SET ended_at = ?, summary = ?, outcome = ?, "
                "cost_dollars = ?, input_tokens = ?, output_tokens = ?, "
                "tool_calls = ?, cache_read_tokens = ?, cache_write_tokens = ? "
                "WHERE id = ?",
                (time.time(), _enc_field(summary, "episodes.summary"),
                 _enc_field(outcome, "episodes.outcome"), cost_dollars,
                 input_tokens, output_tokens, tool_calls,
                 cache_read_tokens, cache_write_tokens, episode_id),
            )

    def list_episodes(
        self,
        limit: int = 50,
        goal_id: int | None = None,
        owner: str | None = None,
    ) -> list[EpisodeSpend]:
        """Recent run-cost episodes, newest first.

        ``owner`` scopes to one principal's runs by joining ``episodes`` to the
        owning goal (the episodes table has no owner column of its own).
        ``None`` is the admin / auth-off view — every principal's episodes.
        Without this filter ``/api/v1/spend`` returned every user's runs + cost
        to any caller.
        """
        cols = _EPISODE_SPEND_COLS
        join = ("FROM episodes e JOIN goals g ON e.goal_id = g.id "
                if owner is not None else "FROM episodes e ")
        where, params = [], []
        if goal_id is not None:
            where.append("e.goal_id = ?")
            params.append(goal_id)
        if owner is not None:
            where.append("g.owner = ?")
            params.append(owner)
        sql = "SELECT " + cols + join
        if where:
            sql += "WHERE " + " AND ".join(where) + " "
        sql += "ORDER BY e.started_at DESC LIMIT ?"
        params.append(limit)
        rows = self._read_all(sql, tuple(params))
        return _episode_spends_from_rows(rows)

    def total_spend(self, owner: str | None = None, *,
                    since: float | None = None) -> dict[str, float]:
        """Aggregate spend. ``owner`` scopes to one principal's runs (join to
        the owning goal); ``None`` is the deployment-wide admin / auth-off view.
        ``since`` keeps only runs that started at or after that time (the
        "this month" figure on the My work page and in the daily summary).
        """
        join = ("FROM episodes e JOIN goals g ON e.goal_id = g.id "
                if owner is not None else "FROM episodes e ")
        where = "WHERE e.ended_at IS NOT NULL"
        params: tuple = ()
        if owner is not None:
            where += " AND g.owner = ?"
            params = (owner,)
        if since is not None:
            where += " AND e.started_at >= ?"
            params = (*params, float(since))
        row = self._read_one(
            "SELECT COALESCE(SUM(e.cost_dollars), 0) AS dollars, "
            "COALESCE(SUM(e.input_tokens), 0) AS in_tok, "
            "COALESCE(SUM(e.output_tokens), 0) AS out_tok, "
            "COUNT(*) AS runs " + join + where,
            params,
        )
        return {
            "dollars": row["dollars"],
            "input_tokens": row["in_tok"],
            "output_tokens": row["out_tok"],
            "runs": row["runs"],
        }

    def agent_spend_groups(self, *, since: float, until: float) -> list[AgentSpendGroup]:
        """Aggregate completed outside-agent episodes in this workspace."""
        rows = self._read_all(
            "SELECT g.owner, g.domain, strftime('%Y-%m', CAST(e.ended_at AS INTEGER), 'unixepoch') AS month, "
            "COALESCE(SUM(e.cost_dollars), 0), COUNT(*) "
            "FROM episodes e JOIN goals g ON e.goal_id = g.id "
            "WHERE e.ended_at >= ? AND e.ended_at < ? AND substr(g.owner, 1, 6) = 'agent:' "
            "AND length(g.owner) > 6 GROUP BY g.owner, g.domain, month",
            (since, until),
        )
        return [AgentSpendGroup(*row) for row in rows]

    # ----- goal events -----
    def append_event(self, goal_id: int, agent: str, kind: str, content: str) -> int:
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goal_events(goal_id, agent, kind, content, ts) VALUES(?, ?, ?, ?, ?)",
                (goal_id, agent, kind, _enc_field(content, "goal_events.content"), time.time()),
            )
            self._goal_changed(goal_id)
            return cur.lastrowid

    # ----- approvals (high-risk action queue) -----
    def create_approval(
        self,
        action: str,
        *,
        risk: str = "medium",
        scope: str | None = None,
        detail: str | None = None,
        provenance: str | None = None,
        approvals_required: int = 1,
        requested_by: str | None = None,
        undoable: bool = False,
    ) -> int:
        """Park a high-risk action for out-of-band (dashboard) approval.

        ``provenance`` is trusted caller-supplied metadata used by operator UIs;
        it must not be inferred from ``detail``, which may contain untrusted
        model, user, or remote-server text.

        ``approvals_required`` is the quorum (N) of DISTINCT approvers needed
        before the action is granted (segregation of duties; 1 = legacy single
        approver). ``requested_by`` is the requesting principal, so a multi-party
        approval can bar the requester from approving their own request.
        ``undoable`` is only for a requester that waits out the undo window
        before acting on a decision (the consent wait, which then calls
        :meth:`settle_approval_decision`); every other decision is final.
        """
        from .logging_config import current_goal_id

        context_goal = current_goal_id()
        with self._writing() as conn:
            goal = conn.execute("SELECT id, domain FROM goals WHERE id = ?", (context_goal,)).fetchone()
            cur = conn.execute(
                "INSERT INTO approvals(action, risk, scope, detail, provenance, "
                "status, requested_at, approvals_required, requested_by, goal_id, department, "
                "undo_hold) VALUES(?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)",
                (_enc_field(action, "approvals.action"), risk, _enc_field(scope, "approvals.scope"),
                 _enc_field(detail, "approvals.detail"),
                 provenance, time.time(), max(1, int(approvals_required)),
                 (requested_by or None), goal["id"] if goal else None,
                 goal["domain"] if goal else "",
                 APPROVAL_UNDO_OPEN if undoable else None),
            )
            approval_id = cur.lastrowid
        _notify_approval_created(self, approval_id, provenance)
        self._emit_approval_event("approval.created", approval_id, {"risk": risk, "action": action})
        return approval_id

    def _emit_approval_event(self, event: str, approval_id: int, payload: dict) -> None:
        """Webhook subscribers hear about approvals; never raises, and costs one
        read of the subscription table when nobody is subscribed."""
        if event == "approval.decided":
            _notify_approval_decided(self, approval_id)
        try:
            from .webhook_events import emit, record_link

            emit(event, record_type="approval", record_id=str(approval_id),
                 title=str(payload.get("action") or "approval")[:200],
                 summary={k: v for k, v in payload.items() if k != "action"},
                 link=record_link("/approvals"), payload=dict(payload), world=self)
        except Exception:  # pragma: no cover - webhooks never block an approval
            pass

    def get_approval(self, approval_id: int, *, strict_tenant: bool = False) -> Approval | None:
        row = self._read_one(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        )
        return _approval_from_row(row) if row else None

    def list_approvals(self, limit: int = 500) -> list[Approval]:
        """All approvals, newest first (the Operating Record's human-decision
        feed); ``pending_approvals`` remains the queue view."""
        rows = self._read_all(
            "SELECT * FROM approvals ORDER BY requested_at DESC, id DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        return _approvals_from_rows(rows)

    def pending_unattached_approvals(
        self, owner: str, *, limit: int, since: float,
    ) -> tuple[list[Approval], bool]:
        """Read one bounded snapshot, stopping at the first old request."""
        from .crypto_at_rest import at_rest_enabled

        rows = self._read_all(
            "SELECT * FROM approvals WHERE status='pending' AND goal_id IS NULL "
            "AND requested_by=? ORDER BY id DESC LIMIT ?", (owner, limit + 1),
        )
        for index, row in enumerate(rows[:limit]):
            if float(row["requested_at"] or 0) <= since:
                rows = rows[:index]
                break
        else:
            if len(rows) > limit:
                return [], False
        if not rows:
            return [], True
        at_rest = at_rest_enabled()
        key_cache: dict[tuple[str, bytes], object] = {}
        return [_approval_from_row(row, at_rest=at_rest, key_cache=key_cache) for row in rows], True

    def pending_approvals(self) -> list[Approval]:
        rows = self._read_all(
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY id"
        )
        return _approvals_from_rows(rows)

    def approval_audit_event_id(
        self,
        approval_id: int,
        status: str,
        decided_by: str,
    ) -> str:
        """Deterministic idempotency id for an exact approval vote."""
        return _approval_audit_event_id(
            current_tenant_id(),
            approval_id,
            status,
            (decided_by or "").strip(),
            self._approval_undo_round(approval_id),
        )

    def _approval_undo_round(self, approval_id: int, conn=None) -> int:
        """How many times this approval was undone (see ``undo_approval_decision``)."""
        sql = (
            "SELECT COUNT(*) FROM approval_audit_outbox "
            "WHERE approval_id = ? AND status = ?"
        )
        params = (int(approval_id), APPROVAL_UNDO_STATUS)
        row = conn.execute(sql, params).fetchone() if conn is not None else self._read_one(sql, params)
        return int(row[0]) if row else 0

    def get_approval_audit_event(
        self,
        event_id: str,
    ) -> ApprovalAuditEvent | None:
        row = self._read_one(
            "SELECT event_id, approval_id, status, decided_by, final_status, "
            "created_at, delivered_at FROM approval_audit_outbox "
            "WHERE event_id = ?",
            (str(event_id),),
        )
        return _approval_audit_event_from_row(row) if row else None

    def pending_approval_audit_events(
        self,
        *,
        approval_id: int | None = None,
        limit: int = 100,
    ) -> list[ApprovalAuditEvent]:
        """Undelivered approval audit events, oldest first."""
        sql = (
            "SELECT event_id, approval_id, status, decided_by, final_status, "
            "created_at, delivered_at FROM approval_audit_outbox "
            "WHERE delivered_at IS NULL"
        )
        params: tuple[Any, ...] = ()
        if approval_id is not None:
            sql += " AND approval_id = ?"
            params = (int(approval_id),)
        sql += " ORDER BY created_at, event_id LIMIT ?"
        params += (max(1, min(int(limit), 1000)),)
        return [
            _approval_audit_event_from_row(row)
            for row in self._read_all(sql, params)
        ]

    def approval_has_pending_finalization(self, approval_id: int) -> bool:
        """Whether an accepted final vote is waiting on signed audit delivery."""
        row = self._read_one(
            "SELECT 1 FROM approval_audit_outbox "
            "WHERE approval_id = ? AND final_status IS NOT NULL "
            "AND delivered_at IS NULL LIMIT 1",
            (int(approval_id),),
        )
        return row is not None

    @staticmethod
    def _check_effect_guard(effect_guard):
        if effect_guard is not None:
            effect_guard()

    def decide_approval_audited(
        self,
        approval_id: int,
        status: str,
        *,
        decided_by: str,
        reviewed_card: dict | None = None,
        effect_guard=None,
    ) -> ApprovalAuditEvent | None:
        """Atomically accept a vote and queue its signed-audit delivery.

        Unlike :meth:`decide_approval`, this does not make a final approval
        effective in the same transaction.  It records the sign-off plus a
        deterministic outbox event together, and
        :meth:`mark_approval_audit_delivered` applies the final status only once
        every event for this approval has reached the audit chain.

        A retry of the same ``(approval, status, supervisor)`` returns the
        original event even if the approval is now final.  That makes a retry
        safe after a database commit acknowledgement is lost.
        """
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        approver = (decided_by or "").strip()
        if not approver:
            return None
        with self._writing() as conn:
            # The no-op write acquires SQLite's cross-process write reservation
            # before any decision read.  A SELECT-first deferred transaction can
            # otherwise race another process and fail with BUSY_SNAPSHOT.
            pending = conn.execute(
                "UPDATE approvals SET status = status "
                "WHERE id = ? AND status = 'pending'",
                (int(approval_id),),
            ).rowcount > 0
            self._check_effect_guard(effect_guard)
            undo_round = self._approval_undo_round(approval_id, conn)
            event_id = _approval_audit_event_id(
                current_tenant_id(), approval_id, status, approver, undo_round,
            )

            if reviewed_card is not None:
                from .approval_vote_review import require_locked_vote_review

                locked = conn.execute("SELECT * FROM approvals WHERE id = ?", (int(approval_id),)).fetchone()
                approval = _approval_from_row(locked) if locked is not None else None
                signoffs = conn.execute("SELECT approver, decision FROM approval_signoffs WHERE approval_id = ? ORDER BY decided_at", (int(approval_id),)).fetchall()
                approvers = _single_approver(approval, [row["approver"] for row in signoffs if row["decision"] == "approved"]) if approval is not None else []
                audit_pending = int(conn.execute("SELECT COUNT(*) FROM approval_audit_outbox WHERE approval_id = ? AND delivered_at IS NULL", (int(approval_id),)).fetchone()[0])
                content_owner = (approval.requested_by or "") if approval is not None else None
                if approval is not None and approval.goal_id:
                    source = conn.execute("SELECT owner,domain FROM goals WHERE id = ?", (approval.goal_id,)).fetchone()
                    content_owner = (source["owner"] or "") if source is not None else None
                    source_guard = getattr(effect_guard, "approval_source", None)
                    if source_guard is not None:
                        source_guard(approval.goal_id, content_owner, source["domain"] if source is not None else None)
                require_locked_vote_review(approval, reviewed_card, status=status, actor=approver,
                                           event_id=event_id, approvers=approvers, audit_pending=audit_pending,
                                           content_owner=content_owner)

            prior = conn.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                "WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if prior is not None:
                prior_event = _approval_audit_event_from_row(prior)
                if not prior_event.matches(approval_id, status, approver):
                    raise RuntimeError(
                        "approval audit outbox event identity is corrupt"
                    )
                return prior_event
            if not pending:
                return None

            row = conn.execute(
                "SELECT approvals_required, requested_by "
                "FROM approvals WHERE id = ? AND status = 'pending'",
                (int(approval_id),),
            ).fetchone()
            if row is None:
                return None

            # Once a vote has selected a final outcome, freeze the approval
            # while its audit row is pending.  A competing approve/deny must not
            # race the signed authority boundary.
            if conn.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = ? AND final_status IS NOT NULL "
                "AND delivered_at IS NULL LIMIT 1",
                (int(approval_id),),
            ).fetchone() is not None:
                return None

            required = max(1, int(row["approvals_required"] or 1))
            requested_by = row["requested_by"]
            if (
                required > 1
                and status == "approved"
                and requested_by
                and _same_person(approver, requested_by)
            ):
                from .safety.dual_control import allow_self_approval

                if not allow_self_approval():
                    return None

            now = time.time()
            final_status: str | None = None
            if required <= 1:
                final_status = status
            else:
                # Upgrade seam: v21-v29 could leave a pending N-of-M approval
                # with one or more signoffs but no transactional outbox rows.
                # Queue those historical votes before accepting a new one, so
                # a quorum can never become effective with only its last vote
                # represented in the signed chain.
                for legacy in conn.execute(
                    "SELECT approver, decision, decided_at "
                    "FROM approval_signoffs WHERE approval_id = ? "
                    "ORDER BY decided_at, approver",
                    (int(approval_id),),
                ).fetchall():
                    legacy_event_id = _approval_audit_event_id(
                        current_tenant_id(),
                        approval_id,
                        legacy["decision"],
                        legacy["approver"],
                        undo_round,
                    )
                    conn.execute(
                        "INSERT OR IGNORE INTO approval_audit_outbox("
                        "event_id, approval_id, status, decided_by, final_status, "
                        "created_at, delivered_at) "
                        "VALUES(?, ?, ?, ?, NULL, ?, NULL)",
                        (
                            legacy_event_id,
                            int(approval_id),
                            legacy["decision"],
                            legacy["approver"],
                            float(legacy["decided_at"]),
                        ),
                    )
                prior = conn.execute(
                    "SELECT event_id, approval_id, status, decided_by, final_status, "
                    "created_at, delivered_at FROM approval_audit_outbox "
                    "WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if prior is not None:
                    prior_event = _approval_audit_event_from_row(prior)
                    if not prior_event.matches(approval_id, status, approver):
                        raise RuntimeError(
                            "approval audit outbox event identity is corrupt"
                        )
                    return prior_event

                existing_signoff = conn.execute(
                    "SELECT decision FROM approval_signoffs "
                    "WHERE approval_id = ? AND approver = ?",
                    (int(approval_id), approver),
                ).fetchone()
                # A signed human vote is immutable.  The old immediate method
                # retains its compatibility semantics, but the governed
                # dashboard path never silently rewrites one decision into the
                # opposite decision.
                if (
                    existing_signoff is not None
                    and existing_signoff["decision"] != status
                ):
                    return None
                conn.execute(
                    "INSERT INTO approval_signoffs(approval_id, approver, decision, "
                    "decided_at) VALUES(?, ?, ?, ?) "
                    "ON CONFLICT(approval_id, approver) DO NOTHING",
                    (int(approval_id), approver, status, now),
                )
                if status == "denied":
                    final_status = "denied"
                else:
                    approved = _people(conn.execute(
                        "SELECT approver FROM approval_signoffs "
                        "WHERE approval_id = ? AND decision = 'approved'",
                        (int(approval_id),),
                    ).fetchall())
                    if approved >= required:
                        final_status = "approved"

            conn.execute(
                "INSERT INTO approval_audit_outbox("
                "event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at) VALUES(?, ?, ?, ?, ?, ?, NULL)",
                (
                    event_id,
                    int(approval_id),
                    status,
                    approver,
                    final_status,
                    now,
                ),
            )
            result = ApprovalAuditEvent(
                event_id=event_id,
                approval_id=int(approval_id),
                status=status,
                decided_by=approver,
                final_status=final_status,
                created_at=now,
                delivered_at=None,
            )
            self._check_effect_guard(effect_guard)
            return result

    def mark_approval_audit_delivered(
        self,
        event_id: str,
        *,
        delivered_at: float | None = None,
        effect_guard=None,
    ) -> bool:
        """Acknowledge signed delivery and apply any now-safe final outcome.

        The delivery marker and final approval update share one transaction.
        Repeating the call is idempotent.  If an audit append succeeded but the
        commit acknowledgement is lost, the caller can safely append the same
        stable ``event_id`` again and retry this method.
        """
        finalized: tuple[str, str] | None = None
        with self._writing() as conn:
            # A no-op write first opens the write transaction, so the reads
            # below cannot see state another process changes before the
            # final UPDATE (Python sqlite begins only at the first DML).
            conn.execute("UPDATE approval_audit_outbox SET delivered_at=delivered_at WHERE event_id=?", (str(event_id),))
            if effect_guard is not None:
                effect_guard()
            event = conn.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                "WHERE event_id = ?",
                (str(event_id),),
            ).fetchone()
            if event is None:
                return False
            source_guard = getattr(effect_guard, "approval_source", None)
            if source_guard is not None:
                source = conn.execute("SELECT g.id,g.owner,g.domain FROM approvals a JOIN goals g ON g.id=a.goal_id WHERE a.id=?", (event["approval_id"],)).fetchone()
                if source is None:
                    raise PermissionError("The original approval task is unavailable")
                source_guard(source[0], source[1] or "", source[2])
            delivery_time = (
                float(event["delivered_at"])
                if event["delivered_at"] is not None
                else float(delivered_at) if delivered_at is not None else time.time()
            )
            if event["delivered_at"] is None:
                conn.execute(
                    "UPDATE approval_audit_outbox SET delivered_at = ? "
                    "WHERE event_id = ? AND delivered_at IS NULL",
                    (
                        delivery_time,
                        str(event_id),
                    ),
                )

            approval_id = int(event["approval_id"])
            still_pending = conn.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = ? AND delivered_at IS NULL LIMIT 1",
                (approval_id,),
            ).fetchone()
            if still_pending is None:
                final = conn.execute(
                    "SELECT final_status, decided_by, created_at "
                    "FROM approval_audit_outbox "
                    "WHERE approval_id = ? AND final_status IS NOT NULL "
                    "ORDER BY created_at DESC, event_id DESC LIMIT 1",
                    (approval_id,),
                ).fetchone()
                if final is not None:
                    applied = conn.execute(
                        "UPDATE approvals SET status = ?, decided_at = ?, "
                        "decided_by = ? WHERE id = ? AND status = 'pending'",
                        (
                            final["final_status"],
                            delivery_time,
                            final["decided_by"],
                            approval_id,
                        ),
                    ).rowcount
                    if applied:
                        finalized = (final["final_status"], final["decided_by"])
            self._check_effect_guard(effect_guard)
        # Subscribers hear of the decision only once the guard has passed and the
        # transaction has committed; a rollback must not leave "approved" sent.
        if finalized is not None:
            self._emit_approval_event("approval.decided", approval_id,
                                      {"status": finalized[0], "decided_by": finalized[1] or ""})
        return True

    def approval_state(self, approval_id: int) -> dict | None:
        """Quorum progress for an approval, or None if unknown. Shape:
        ``{status, approvals_required, approved_count, approvers, requested_by}``
        -- the operator/UI view of an in-flight N-of-M decision."""
        appr = self.get_approval(approval_id)
        if appr is None:
            return None
        rows = self._read_all(
            "SELECT approver, decision FROM approval_signoffs "
            "WHERE approval_id = ? ORDER BY decided_at, approver", (approval_id,),
        )
        approvers = [r["approver"] for r in rows if r["decision"] == "approved"]
        approvers = _single_approver(appr, approvers)
        audit_pending = int(
            self._read_one(
                "SELECT COUNT(*) FROM approval_audit_outbox "
                "WHERE approval_id = ? AND delivered_at IS NULL",
                (approval_id,),
            )[0]
        )
        return _approval_state_view(appr, approvers, audit_pending)

    def pending_approval_signoffs(self, approval_ids: list[int]) -> dict[int, list[str]]:
        """Approved votes for the requested rows that are still pending."""
        result: dict[int, list[str]] = {}
        for chunk in self._chunks(approval_ids):
            placeholders = ", ".join("?" for _ in chunk)
            rows = self._read_all(
                "SELECT a.id, s.approver FROM approvals a LEFT JOIN approval_signoffs s "
                "ON s.approval_id = a.id AND s.decision = 'approved' "
                f"WHERE a.status = 'pending' AND a.id IN ({placeholders}) "
                "ORDER BY a.id, s.decided_at, s.approver", tuple(chunk),
            )
            for approval_id, approver in rows:
                votes = result.setdefault(approval_id, [])
                if approver is not None:
                    votes.append(approver)
        return result

    @staticmethod
    def _chunks(values: list[int], size: int = 500) -> Iterator[list[int]]:
        for index in range(0, len(values), size):
            yield values[index:index + size]

    # ----- channel dedup -----
    def mark_message_processed(
        self,
        channel: str,
        external_id: str,
        goal_id: int | None = None,
    ) -> bool:
        """Record an inbound message as processed; idempotent.

        Returns True on first-write (the caller should run the goal),
        False on duplicate (the caller should return 200 without
        re-running). Twilio retries within 15s if the webhook is slow
        or non-2xx; the same MessageSid arriving twice was producing
        N goals and N spends before this.
        """
        try:
            with self._writing() as conn:
                conn.execute(
                    "INSERT INTO processed_messages(channel, external_id, goal_id, seen_at) "
                    "VALUES(?, ?, ?, ?)",
                    (channel, external_id, goal_id, time.time()),
                )
            return True
        except sqlite3.IntegrityError:
            if self._read_one(
                "SELECT 1 FROM processed_messages WHERE channel = ? AND external_id = ?",
                (channel, external_id),
            ) is not None:
                return False
            raise

    def release_processed_message(self, channel: str, external_id: str) -> None:
        """Undo a claim made by ``mark_message_processed`` so a retry can
        re-process the message.

        Channels claim the dedup row BEFORE running the goal (atomic, so a
        Twilio retry that races a slow handler is a no-op instead of a
        double-spend). If that run then fails, the claim must be released or
        the message is stuck marked-as-done and never retried.
        """
        with self._writing() as conn:
            conn.execute(
                "DELETE FROM processed_messages "
                "WHERE channel = ? AND external_id = ?",
                (channel, external_id),
            )

    # ----- cluster-wide killswitch (v22) -----
    # Untenanted, single-row global emergency stop. On a shared backend
    # (Postgres) every replica's killswitch.check() consults this, so a halt
    # armed via the dashboard stops the whole fleet rather than just the replica
    # that served the request.
    def arm_halt(self, reason: str = "", source: str = "manual",
                 armed_by: str = "") -> str:
        generation = secrets.token_urlsafe(24)
        with self._writing() as conn:
            conn.execute(
                "INSERT INTO halt(scope, reason, source, armed_by, armed_at, generation) "
                "VALUES('', ?, ?, ?, ?, ?) "
                "ON CONFLICT(scope) DO UPDATE SET reason=excluded.reason, "
                "source=excluded.source, armed_by=excluded.armed_by, "
                "armed_at=excluded.armed_at, generation=excluded.generation",
                (
                    reason or "",
                    source or "manual",
                    armed_by or "",
                    time.time(),
                    generation,
                ),
            )
        return generation

    def disarm_halt(
        self,
        *,
        expected_generation: str,
        durable_clear: Callable[[], None] | None = None,
    ) -> bool:
        """Atomically bind a durable local clear to the observed shared HALT.

        The write transaction is acquired before ``durable_clear`` runs.  A
        callback failure rolls the shared mutation back; a concurrent arm must
        wait and therefore lands after this generation-bound delete instead of
        being erased by it.
        """
        if not isinstance(expected_generation, str):
            raise TypeError("expected_generation must be a string")
        with self._writing() as conn:
            # ``_writing`` serializes this object; BEGIN IMMEDIATE also claims
            # the SQLite database writer slot before the filesystem callback,
            # covering other WorldModel connections/processes.
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT generation FROM halt WHERE scope = ''",
            ).fetchone()
            if row is None or (row[0] or "") != expected_generation:
                return False
            if durable_clear is not None:
                durable_clear()
            cursor = conn.execute(
                "DELETE FROM halt WHERE scope = '' AND generation = ?",
                (expected_generation,),
            )
            deleted = cursor.rowcount
        return bool(deleted and deleted > 0)

    def active_halt(self) -> dict | None:
        """The shared global halt state, or ``None`` when not armed."""
        row = self._read_one(
            "SELECT reason, source, armed_by, armed_at, generation "
            "FROM halt WHERE scope = ''",
            (),
        )
        if row is None:
            return None
        return {"reason": row[0] or "", "source": row[1] or "",
                "armed_by": row[2] or "", "armed_at": row[3],
                "generation": row[4] or ""}


def reclaim_window_seconds(default: float = 60.0) -> float:
    """The orphan-reclaim staleness window in seconds.

    ``MAVERICK_ORPHAN_RECLAIM_SECONDS`` when set and valid, else ``default``
    — exactly the precedence :meth:`WorldModel.reclaim_orphan_goals` has
    always applied. Public so out-of-process work (external-agent
    heartbeats) can tell callers how often they must refresh liveness."""
    import os
    raw = os.environ.get("MAVERICK_ORPHAN_RECLAIM_SECONDS")
    if raw is None:
        # ``[world_model] orphan_reclaim_seconds`` (All settings); env wins.
        try:
            from .config import load_config
            raw = ((load_config() or {}).get("world_model") or {}).get("orphan_reclaim_seconds")
        except Exception:
            raw = None
    if raw is not None:
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            pass
    return default


class WorldBackendUnreadable(RuntimeError):
    """Postgres was the last database used, but the configuration that names
    the database cannot be read. Opening the local database instead would
    write work where nobody looks, so Second Shift refuses to start."""


def _world_backend_marker() -> Path:
    # Deployment-wide, like the Postgres backend itself: never tenant-scoped.
    return data_dir("world_backend", tenant=None)


def _record_world_backend(backend: str) -> None:
    """Remember that this install used Postgres, or deliberately left it (best
    effort). An install that only ever used the local database has no marker."""
    marker = _world_backend_marker()
    try:
        if marker.is_file() and marker.read_text(encoding="utf-8").strip() == backend:
            return
        from .file_lock import atomic_write_text

        marker.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(marker, backend + "\n")
    except OSError:
        log.warning("could not record the world database in use at %s", marker, exc_info=True)


_WORLD_BACKENDS = ("sqlite", "postgres")
_LOCAL_ON_PURPOSE = (
    'To use the local database on purpose, set [world_model] backend = "sqlite" '
    "in the settings file, or set MAVERICK_WORLD_BACKEND=sqlite."
)


def _last_world_backend() -> str:
    marker = _world_backend_marker()
    try:
        return marker.read_text(encoding="utf-8").strip() if marker.is_file() else ""
    except OSError:
        return ""


def _refuse_silent_local_fallback() -> None:
    """Refuse the local database when Postgres may have been lost.

    The backend comes from ``MAVERICK_WORLD_BACKEND`` or ``[world_model]
    backend``; only ``sqlite`` and ``postgres`` are understood and anything
    else is an error, never a fallback. Once Postgres was used, opening the
    local database needs an explicit ``sqlite`` choice: settings that cannot
    be read, or that do not name a backend, are refused. A machine that has
    only ever used the local database keeps working.
    """
    env = os.environ.get("MAVERICK_WORLD_BACKEND", "").strip().lower()
    if env and env not in _WORLD_BACKENDS:
        raise WorldBackendUnreadable(
            f"MAVERICK_WORLD_BACKEND is {env!r}, which Second Shift does not understand. "
            'Use "sqlite" for the local database or "postgres" for the shared one.'
        )
    if env:
        # An explicit choice (postgres was handled by the caller). Remember a
        # deliberate move away from Postgres so later starts need no flag. A
        # machine that never used Postgres has no marker and gets none: opening
        # the local database must not write anything beside it.
        if _last_world_backend() == "postgres":
            _record_world_backend("sqlite")
        return
    from .config import config_path, config_source_errors, load_config

    errors = config_source_errors(include_tenant=True)
    last = _last_world_backend()
    if errors:
        if last != "postgres":
            return
        problems = "; ".join(f"{path}: {message}" for path, message in sorted(errors.items()))
        raise WorldBackendUnreadable(
            "Second Shift last used its Postgres database, but its settings cannot be "
            f"read: {problems}. Fix that file and start again; Second Shift will not "
            f"switch to a local database on its own. {_LOCAL_ON_PURPOSE}"
        )
    section = load_config().get("world_model") or {}
    raw = section.get("backend") if isinstance(section, dict) else None
    choice = raw.strip().lower() if isinstance(raw, str) else raw
    if choice not in (None, "", *_WORLD_BACKENDS):
        raise WorldBackendUnreadable(
            f"[world_model] backend is {raw!r} in {config_path()} (or a settings "
            "overlay), which Second Shift does not understand. Use "
            '"sqlite" for the local database or "postgres" for the shared one.'
        )
    if last != "postgres":
        return
    if choice == "sqlite":
        _record_world_backend("sqlite")
        return
    raise WorldBackendUnreadable(
        "Second Shift last used its Postgres database, but its settings no longer "
        "choose a database, so it will not switch to a local database on its "
        'own. To keep using Postgres, set [world_model] backend = "postgres". '
        f"{_LOCAL_ON_PURPOSE}"
    )


def open_world(path: Path | None = None) -> Any:
    """Open the configured world-model backend.

    Returns the SQLite ``WorldModel`` by default. When the user opts into
    Postgres (``[world_model] backend = "postgres"`` in config.toml or
    ``MAVERICK_WORLD_BACKEND=postgres``), returns a ``PostgresWorldModel``
    whose public surface mirrors ``WorldModel``; the ``path`` argument is
    ignored in that case (Postgres uses a DSN, not a file).

    **Client/tenant floor:** when called with no explicit ``path`` and the
    deployment is bound to a client (or a tenant is active), the canonical
    world resolves to that client's isolated ``tenants/<client>/world.db`` via
    :func:`world_for_tenant`, NOT the un-scoped ``~/.maverick/world.db``. This
    keeps the channel server (``serve``), the goal runner/worker, the gRPC goal
    API and the dashboard all opening the SAME per-client world DB (one SQLite
    file = one cached ``WorldModel``); without it a client-bound ``serve`` wrote
    goals to the shared root while the dashboard read the floored path, silently
    splitting the world. Passing an explicit ``path`` (tests, CLI ``--db``)
    bypasses the floor and is unchanged.

    The Postgres backend (and its ``psycopg`` dependency) is imported only
    when selected, so the default SQLite path stays dependency-free and the
    kernel runs without psycopg installed.

    **At-rest encryption:** the Postgres backend now seals the same sensitive
    content columns as SQLite (goal title/description/result, messages, turns,
    episodes, facts, questions, approvals, artifacts, projects, sign-off notes,
    event bodies) with the shared AES-256-GCM field codec, so encryption-at-rest
    is supported on Postgres too. Text search over sealed columns transparently
    falls back to scan-then-decrypt.
    """
    from .world_model_backends import is_postgres_configured

    if is_postgres_configured():
        from . import practice

        if practice.active():  # the practice world is a local file; never write practice live
            raise practice.PracticeUnavailable(practice.POSTGRES_REASON)
        from .world_model_backends import open_postgres_world

        world = open_postgres_world()
        _record_world_backend("postgres")
        return world
    if path is None or Path(path) in (DEFAULT_DB, data_dir("world.db")):
        _refuse_silent_local_fallback()
    if path is None:
        # No explicit path: honor the client/tenant floor so every canonical
        # world entry point opens the one per-client DB (see docstring).
        from .paths import current_tenant_id
        tid = current_tenant_id()
        if tid:
            return world_for_tenant(tid)
        return WorldModel()
    return WorldModel(path, _managed_path=Path(path) == data_dir("world.db"))


# Per-tenant WorldModel cache. Multi-tenancy: each tenant gets its own
# world.db under ~/.maverick/tenants/<t>/, mirroring how cross-session memory
# (tools/memory.py) and the audit log resolve their dirs via data_dir(). Keyed
# by the RESOLVED db path so two raw tenant ids that sanitize to the same dir
# share one connection -- a single SQLite file must have exactly one WorldModel
# (its write lock serialises mutations within the process; two instances on the
# same file would not coordinate). Cached for the life of the process, like the
# audit log's default singleton: WorldModel opens with check_same_thread=False +
# WAL + a write lock, so one instance is safely shared across the FastAPI
# threadpool / goal tasks.
MAX_TENANT_WORLDS = 128
# LRU cache of per-tenant WorldModels (insertion/access order = recency). An
# OrderedDict so a full cache evicts the least-recently-used tenant instead of
# hard-failing the next one.
_tenant_worlds: OrderedDict[str, WorldModel] = OrderedDict()
_tenant_worlds_lock = threading.Lock()


def _world_cache_key(path: Path) -> str:
    """Host-independent key that cannot split a case-insensitive DB path."""
    return os.path.normcase(os.path.abspath(os.fspath(path))).casefold()


def world_for_tenant(tenant: str | None = None) -> WorldModel:
    """Return the process-cached ``WorldModel`` for ``tenant``.

    ``tenant=None`` is the legacy shared world at ``~/.maverick/world.db``
    (single-tenant behaviour unchanged); a tenant ``t`` gets an isolated
    ``~/.maverick/tenants/<t>/world.db``. The path is resolved via
    :func:`maverick.paths.data_dir`, the same primitive memory + audit use, so
    world/memory/audit all land under the same tenant dir.

    Repeated calls for the same tenant return the SAME instance. The cache holds
    up to ``MAX_TENANT_WORLDS`` tenant connections as an LRU: reaching the
    ceiling EVICTS the least-recently-used tenant (so a busy fleet of many
    tenants keeps working) rather than raising. The legacy shared (``None``)
    world is never evicted. Eviction drops the cache reference only -- it does
    not force-close the connection (an in-flight caller may still hold it); the
    underlying SQLite connection is reclaimed when its last reference drops.
    Does NOT consult the Postgres backend -- it is the per-tenant SQLite factory
    the server uses for goal/conversation/turn writes.
    """
    if tenant is not None:
        tenant = bind_tenant_namespace(tenant)
    from . import practice

    path = practice.world_path(tenant) if practice.active() else data_dir("world.db", tenant=tenant)
    key = _world_cache_key(path)
    shared_key = _world_cache_key(data_dir("world.db", tenant=None))
    with _tenant_worlds_lock:
        world = _tenant_worlds.get(key)
        if world is not None:
            _tenant_worlds.move_to_end(key)  # mark most-recently-used
            return world
        if tenant is not None and len(_tenant_worlds) >= MAX_TENANT_WORLDS:
            _evict_lru_tenant_world(shared_key)
        world = WorldModel(path, _managed_path=True)
        # Ownership outlives LRU membership: eviction deliberately drops only
        # the cache reference because an in-flight caller may still hold this
        # connection. Teardown helpers must therefore never close an instance
        # merely because another tenant evicted its key in the meantime.
        world._maverick_cache_owned = True
        _tenant_worlds[key] = world
        _tenant_worlds.move_to_end(key)
        return world


def world_is_cached(world: object) -> bool:
    """Return True when ``world`` was created for the per-tenant cache.

    Ownership is durable across LRU eviction because in-flight callers can
    retain an evicted world after it disappears from ``_tenant_worlds``.
    """
    return bool(getattr(world, "_maverick_cache_owned", False))


def close_world_if_owned(world: object) -> None:
    """Close ``world`` unless it is a process-cached tenant world."""
    if world_is_cached(world):
        return
    close = getattr(world, "close", None)
    if callable(close):
        close()


def _evict_lru_tenant_world(shared_key: str) -> None:
    """Drop the least-recently-used TENANT world from the cache (never the
    shared ``None`` world). Caller holds ``_tenant_worlds_lock``."""
    for k in list(_tenant_worlds):  # oldest-first
        if k == shared_key:
            continue
        _tenant_worlds.pop(k, None)
        return
