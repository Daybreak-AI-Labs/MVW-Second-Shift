"""Postgres-backed world model.

A drop-in alternative to the default SQLite WorldModel for users
running Second Shift on a server / cluster who want a shared backend
across processes.

Selected via config:

    [world_model]
    backend = "postgres"
    dsn     = "${MAVERICK_PG_DSN}"   # e.g. postgres://user:pass@host:5432/maverick

Or env:
    MAVERICK_WORLD_BACKEND=postgres
    MAVERICK_PG_DSN=postgres://...

Behind ``maverick-agent[postgres]`` extra (pulls in ``psycopg[binary]``).

Implementation scope: the full ``WorldModel`` surface (goals, projects,
episodes, events, facts, questions, approvals, conversations, erasure,
messages, attachments, the cluster halt and the provider spend ledger).
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass

from ..approval_checks import POSTGRES_SCHEMA as _APPROVAL_CHECK_SCHEMA_PG
from ..attachment_submissions import POSTGRES_SCHEMA as _ATTACHMENT_SUBMISSION_SCHEMA
from ..deadline_alerts import POSTGRES_SCHEMA as _DEADLINE_ALERT_SCHEMA_PG
from ..decision_requests import POSTGRES_SCHEMA as _DECISION_REQUEST_SCHEMA_PG
from ..event_admission import POSTGRES_SCHEMA as _EVENT_ADMISSION_SCHEMA
from ..event_admission import (
    EventRegistryUnavailable,
    LegacyEventGoalHeld,
    compatible_event_goal,
    execution_binding_lock,
)
from ..goal_mutations import SCHEMA as _GOAL_MUTATION_SCHEMA
from ..learning_store_pg_schema import LEARNING_TENANT_MIGRATION
from ..metadata_history import POSTGRES_INDEXES as _HISTORY_INDEXES
from ..personal_alert_revisions import POSTGRES_MIGRATION as _PERSONAL_ALERT_MIGRATION
from ..safety.dual_control import distinct_people, person_key
from ..webhook_subscriptions import POSTGRES_SCHEMA as _WEBHOOK_SUBSCRIPTION_SCHEMA_PG

log = logging.getLogger(__name__)


# Schema mirror. Postgres-flavored types; sequence-based PKs instead of
# AUTOINCREMENT, REAL -> DOUBLE PRECISION, TEXT stays TEXT.
SCHEMA: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS goals (
      id            SERIAL PRIMARY KEY,
      parent_id     INTEGER REFERENCES goals(id),
      title         TEXT NOT NULL,
      description   TEXT,
      status        TEXT NOT NULL DEFAULT 'pending',
      created_at    DOUBLE PRECISION NOT NULL,
      updated_at    DOUBLE PRECISION NOT NULL,
      deadline      DOUBLE PRECISION,
      result        TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_goals_status_updated ON goals(status, updated_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_pg_goals_parent ON goals(parent_id, created_at);",
    """
    CREATE TABLE IF NOT EXISTS episodes (
      id            SERIAL PRIMARY KEY,
      goal_id       INTEGER NOT NULL REFERENCES goals(id),
      started_at    DOUBLE PRECISION NOT NULL,
      ended_at      DOUBLE PRECISION,
      summary       TEXT,
      outcome       TEXT,
      cost_dollars  DOUBLE PRECISION DEFAULT 0,
      input_tokens  INTEGER DEFAULT 0,
      output_tokens INTEGER DEFAULT 0,
      tool_calls    INTEGER DEFAULT 0,
      cache_read_tokens  INTEGER DEFAULT 0,
      cache_write_tokens INTEGER DEFAULT 0
    );
    """,
    # Idempotent add for DBs created before `summary` existed.
    "ALTER TABLE episodes ADD COLUMN IF NOT EXISTS summary TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_pg_episodes_goal_started ON episodes(goal_id, started_at DESC);",
    """
    CREATE TABLE IF NOT EXISTS goal_events (
      id        SERIAL PRIMARY KEY,
      goal_id   INTEGER NOT NULL REFERENCES goals(id),
      agent     TEXT NOT NULL,
      kind      TEXT NOT NULL,
      content   TEXT NOT NULL,
      ts        DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_goal_events_goal_id_id ON goal_events(goal_id, id);",
    """
    CREATE TABLE IF NOT EXISTS facts (
      id            SERIAL PRIMARY KEY,
      key           TEXT NOT NULL UNIQUE,
      value         TEXT NOT NULL,
      updated_at    DOUBLE PRECISION NOT NULL
    );
    """,
    # Idempotent add to mirror the SQLite facts table's episode attribution.
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS source_episode_id INTEGER;",
    """
    CREATE TABLE IF NOT EXISTS questions (
      id          SERIAL PRIMARY KEY,
      goal_id     INTEGER REFERENCES goals(id),
      question    TEXT NOT NULL,
      asked_at    DOUBLE PRECISION NOT NULL,
      answer      TEXT,
      answered_at DOUBLE PRECISION
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
      id           SERIAL PRIMARY KEY,
      action       TEXT NOT NULL,
      risk         TEXT NOT NULL DEFAULT 'medium',
      scope        TEXT,
      detail       TEXT,
      provenance   TEXT,
      status       TEXT NOT NULL DEFAULT 'pending',
      requested_at DOUBLE PRECISION NOT NULL,
      decided_at   DOUBLE PRECISION
    );
    """,
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS provenance TEXT;",
    # Collaborative supervision (claiming + decider attribution) — mirrors
    # the SQLite v13 migration.
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_by TEXT;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_at DOUBLE PRECISION;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_by TEXT;",
    # N-of-M dual control (mirrors SQLite v21).
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approvals_required "
    "INTEGER NOT NULL DEFAULT 1;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS requested_by TEXT;",
    """
    CREATE TABLE IF NOT EXISTS approval_signoffs (
      approval_id INTEGER NOT NULL,
      approver    TEXT NOT NULL,
      decision    TEXT NOT NULL,
      decided_at  DOUBLE PRECISION NOT NULL,
      note        TEXT,
      PRIMARY KEY (approval_id, approver)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_approvals_status ON approvals(status, id);",
    """
    CREATE TABLE IF NOT EXISTS conversations (
      id          SERIAL PRIMARY KEY,
      channel     TEXT NOT NULL,
      user_id     TEXT NOT NULL,
      created_at  DOUBLE PRECISION NOT NULL,
      last_seen   DOUBLE PRECISION NOT NULL,
      UNIQUE(channel, user_id)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_conversations_last_seen ON conversations(last_seen);",
    """
    CREATE TABLE IF NOT EXISTS turns (
      id              SERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id),
      goal_id         INTEGER REFERENCES goals(id),
      role            TEXT NOT NULL,
      content         TEXT NOT NULL,
      ts              DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_turns_conv_id ON turns(conversation_id, id);",
    """
    CREATE TABLE IF NOT EXISTS messages (
      id        SERIAL PRIMARY KEY,
      goal_id   INTEGER REFERENCES goals(id),
      role      TEXT NOT NULL,
      content   TEXT NOT NULL,
      ts        DOUBLE PRECISION NOT NULL
    );
    """,
    # Full-text search index over message content. Postgres has no FTS5; the
    # native equivalent is a GIN index on to_tsvector(...), queried with
    # plainto_tsquery (which safely parses arbitrary natural-language input,
    # the PG analog to the SQLite quoting fix). IMMUTABLE-safe via 'english'.
    "CREATE INDEX IF NOT EXISTS idx_pg_messages_fts "
    "ON messages USING GIN (to_tsvector('english', content));",
    """
    CREATE TABLE IF NOT EXISTS attachments (
      id          SERIAL PRIMARY KEY,
      goal_id     INTEGER NOT NULL REFERENCES goals(id),
      filename    TEXT NOT NULL,
      mime        TEXT NOT NULL,
      size_bytes  INTEGER NOT NULL,
      sha256      TEXT NOT NULL,
      path        TEXT NOT NULL,
      created_at  DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_attachments_goal_id ON attachments(goal_id);",
    """
    CREATE TABLE IF NOT EXISTS processed_messages (
      id           SERIAL PRIMARY KEY,
      channel      TEXT NOT NULL,
      external_id  TEXT NOT NULL,
      goal_id      INTEGER REFERENCES goals(id),
      seen_at      DOUBLE PRECISION NOT NULL,
      UNIQUE(channel, external_id)
    );
    """,
]


# --- Tenancy (migration v10) -------------------------------------------------
# Multi-tenant seam for the shared-Postgres backend. The root tables get a
# nullable ``tenant_id``; child rows (episodes, goal_events, turns, ...) inherit
# their tenant through their goal/conversation FK, so they need no column of
# their own for isolation. ``NULL`` is the legacy single-tenant install
# (``paths.current_tenant()`` returns ``None``), so existing rows and every
# default deployment are unaffected. v10 adds the columns + indexes; writes are
# stamped and reads scoped across all root tables (goals/facts/conversations/
# approvals/processed_messages), with v11 making their global UNIQUE constraints
# tenant-aware so one tenant's upsert can't clobber another's row.
_TENANT_TABLES = ("goals", "facts", "conversations", "approvals", "processed_messages")
# Tables that carry their own ``tenant_id`` and so get a DB-enforced RLS policy.
# Superset of _TENANT_TABLES (which also drives the v10 column-add migration):
# ``projects`` (v15) and ``fact_history`` (v18) gained ``tenant_id`` in their own
# later migrations, so they can't ride the v10 ALTER but MUST still be RLS-scoped
# -- otherwise a PG deployment relying on "the database enforces the boundary"
# leaves those two tables app-layer-only. Child tables (episodes/turns/...) carry
# no tenant_id; their policy checks the parent row (``_RLS_CHILD_TABLES``).
_RLS_TABLES = (
    *_TENANT_TABLES,
    "projects",
    "fact_history",
    "erasure_receipts",
    "approval_audit_outbox",
    "attachment_submissions",
    "event_goal_admissions",
    "event_trigger_batches",
    "webhook_subscriptions",
    "webhook_deliveries",
    "deadline_alerts",
    "encryption_migrations",
    "approval_checks",
    "harness_addenda",
    "harness_corpus",
    "harness_line_meta",
    "harness_transfer_tried",
    "episodes",
    "goal_events",
)
# Tables whose tenant column is not called ``tenant_id``. The webhook and
# deadline-alert tables (v42) scope rows by ``workspace``, which holds the RAW
# tenant id (``webhook_subscriptions.workspace_id``), while every ``tenant_id``
# column holds the path-encoded segment (``slack:U1`` is stored as
# ``slack%3AU1``). Their RLS policy therefore keys on that column and on its
# own session setting, ``maverick.workspace``, which carries the raw id.
_RLS_TENANT_COLUMN: dict[str, str] = {
    "webhook_subscriptions": "workspace",
    "webhook_deliveries": "workspace",
    "deadline_alerts": "workspace",
    "approval_checks": "workspace",
}
# The learning-store tables keep the RAW tenant id in ``tenant_id``
# (``learning_store._active_tenant``), so their policy also compares with
# ``maverick.workspace``.
_RLS_RAW_TENANT_TABLES = ("harness_addenda", "harness_corpus", "harness_line_meta",
                          "harness_transfer_tried")
# The two high-volume child tables (v56) carry a copy of their goal's
# ``tenant_id``, so a workspace-wide read (spend totals, event counts) filters
# on an indexed column instead of probing the parent for every row. Triggers
# keep it in step: it is stamped from the goal on insert and when ``goal_id``
# or the copy is written, and follows the goal when the goal's tenant changes
# (``maverick tenant backfill``). It is never taken from the writer.
_RLS_STAMPED_TABLES = ("episodes", "goal_events")
# The other child tables have no tenant column (v56). A row belongs to the
# workspace of its parent row, so the policy looks the parent up by primary
# key: every write already happens in the parent's scope and backfill moves a
# parent's children with it. A read by parent id costs one index probe.
_RLS_CHILD_TABLES: dict[str, tuple[str, str]] = {
    "approval_signoffs": ("approvals", "approval_id"),
    "artifacts": ("goals", "goal_id"),
    "attachments": ("goals", "goal_id"),
    "decision_requests": ("goals", "goal_id"),
    "goal_mutation_receipts": ("goals", "goal_id"),
    "goal_origins": ("goals", "goal_id"),
    "messages": ("goals", "goal_id"),
    "questions": ("goals", "goal_id"),
    "share_links": ("goals", "goal_id"),
    "signoffs": ("goals", "goal_id"),
    "turns": ("conversations", "conversation_id"),
}


def _rls_setting(table: str) -> str:
    """The session setting ``table``'s policy compares its tenant with."""
    raw = table in _RLS_TENANT_COLUMN or table in _RLS_RAW_TENANT_TABLES
    return "maverick.workspace" if raw else "maverick.tenant"


def _rls_policy_expr(table: str, setting: str | None = None) -> str:
    """The row condition of ``table``'s ``mvk_tenant_isolation`` policy."""
    if table in _RLS_CHILD_TABLES:
        parent, key = _RLS_CHILD_TABLES[table]
        return (f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{key} "
                "AND p.tenant_id = nullif(current_setting('maverick.tenant', true), ''))")
    column = _RLS_TENANT_COLUMN.get(table, "tenant_id")
    return f"{column} = nullif(current_setting('{setting or _rls_setting(table)}', true), '')"


def _rls_check_expr(table: str) -> str:
    """The ``WITH CHECK`` condition: the row condition, and for a turn also its
    goal, so a turn in one workspace's conversation cannot name another's goal."""
    expr = _rls_policy_expr(table)
    if table == "turns":
        expr += (" AND (turns.goal_id IS NULL OR EXISTS (SELECT 1 FROM goals g "
                 "WHERE g.id = turns.goal_id "
                 "AND g.tenant_id = nullif(current_setting('maverick.tenant', true), '')))")
    return expr


def _rls_policy_statement(table: str) -> str:
    return (f"CREATE POLICY mvk_tenant_isolation ON {table} "
            f"USING ({_rls_policy_expr(table)}) WITH CHECK ({_rls_check_expr(table)})")


_TENANT_MIGRATION: list[str] = [
    f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS tenant_id TEXT;" for t in _TENANT_TABLES
] + [
    f"CREATE INDEX IF NOT EXISTS idx_pg_{t}_tenant ON {t}(tenant_id);"
    for t in _TENANT_TABLES
]


# --- Tenant-aware uniqueness (migration v11) ---------------------------------
# The root tables with a global UNIQUE (facts.key, conversations(channel,
# user_id), processed_messages(channel, external_id)) need that uniqueness made
# per-tenant -- otherwise two tenants reusing the same key/channel collide and
# one's write clobbers the other's row. We replace each global UNIQUE with a
# expression unique index over ``COALESCE(tenant_id, '')`` + the natural key:
# version-independent (no PG15 NULLS-NOT-DISTINCT needed), and NULL (the legacy
# single-tenant install) collapses to '' so existing dedup/upsert is preserved
# byte-for-byte. The upserts below target the same expression so ON CONFLICT
# still fires. Dropping the old constraint by its deterministic default name is
# IF EXISTS, so a re-run or a differently-named constraint is a safe no-op.
_TENANT_UNIQUE_MIGRATION: list[str] = [
    "ALTER TABLE facts DROP CONSTRAINT IF EXISTS facts_key_key;",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pg_facts_tenant_key "
    "ON facts (COALESCE(tenant_id, ''), key);",
    "ALTER TABLE conversations DROP CONSTRAINT IF EXISTS conversations_channel_user_id_key;",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pg_conversations_tenant_chan_user "
    "ON conversations (COALESCE(tenant_id, ''), channel, user_id);",
    "ALTER TABLE processed_messages "
    "DROP CONSTRAINT IF EXISTS processed_messages_channel_external_id_key;",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pg_processed_tenant_chan_ext "
    "ON processed_messages (COALESCE(tenant_id, ''), channel, external_id);",
]


# --- Collaborative supervision (migration v13) -------------------------------
# Fresh databases receive these through SCHEMA above. Existing Postgres
# databases that already recorded the v1 base migration need a versioned,
# idempotent migration too; otherwise approval listing/claim/decide paths refer
# to columns that were never added. Keep the version aligned with SQLite's v13
# approval-claiming migration.
_APPROVAL_CLAIMS_MIGRATION: list[str] = [
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_by TEXT;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_at DOUBLE PRECISION;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_by TEXT;",
]


# Ordered schema migrations: ``(version, statements)``. v1 is the consolidated
# base schema (idempotent CREATEs, so a fresh DB and a pre-framework DB both
# converge); higher versions are incremental. The applied set is tracked in the
# ``schema_migrations`` table so a statement runs at most once and the first
# schema change against live customer data has a safe, recorded path.
# --- Goal domain (department pack) (migration v14) ---------------------------
# Parity with the SQLite ``goals.domain`` column: the department pack a goal runs
# as, so learning loops can filter by department without decrypting. Plain-text
# (pack names are operator identifiers, not user content). Fresh DBs add it here;
# existing DBs get the idempotent ALTER.
_GOAL_DOMAIN_MIGRATION: list[str] = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS domain TEXT;",
]


# --- Projects (migration v15) ------------------------------------------------
# Parity with the SQLite ``projects`` table + ``goals.project_id``: a goal can be
# filed under one project (nullable). name/description are sealed at rest via
# ``_seal()`` (encrypted when at-rest encryption is on, same as SQLite); owner/
# domain/status are plaintext for listing + scoping. ``tenant_id`` mirrors the
# v10 tenancy seam so projects isolate per tenant like goals/facts.
_PROJECTS_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS projects (
      id          SERIAL PRIMARY KEY,
      name        TEXT,
      description TEXT,
      owner       TEXT NOT NULL DEFAULT '',
      domain      TEXT NOT NULL DEFAULT '',
      status      TEXT NOT NULL DEFAULT 'active',
      created_at  DOUBLE PRECISION NOT NULL,
      tenant_id   TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_projects_tenant ON projects(tenant_id);",
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS project_id INTEGER;",
    "CREATE INDEX IF NOT EXISTS idx_pg_goals_project ON goals(project_id);",
]


# --- Artifacts (migration v16) -----------------------------------------------
# Parity with the SQLite ``artifacts`` table: deliverables a goal produced
# (markdown/code/table/text), versioned per (goal_id, title). content is sealed
# at rest via ``_seal()`` (encrypted when at-rest encryption is on, same as
# SQLite). Scoped through goal_id's tenant like other child tables, so no
# tenant_id column of its own.
_ARTIFACTS_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS artifacts (
      id          SERIAL PRIMARY KEY,
      goal_id     INTEGER NOT NULL REFERENCES goals(id),
      kind        TEXT NOT NULL DEFAULT 'text',
      title       TEXT,
      content     TEXT,
      version     INTEGER NOT NULL DEFAULT 1,
      created_at  DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_artifacts_goal ON artifacts(goal_id);",
]


# --- Share links / sign-offs / goal origins (migration v17) ------------------
# Parity with the SQLite tables: a revocable expiring read-only share link to a
# goal (only the token's SHA-256 is stored); a human's certify/reject sign-off on
# a deliverable (one row per goal); and which automation spawned a goal. All are
# child tables keyed by goal_id, scoped through the goal's tenant. note is sealed
# at rest via ``_seal()`` (encrypted when at-rest encryption is on, same as SQLite).
_SHARE_SIGNOFF_ORIGIN_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS share_links (
      id           SERIAL PRIMARY KEY,
      goal_id      INTEGER NOT NULL REFERENCES goals(id),
      token_sha256 TEXT NOT NULL UNIQUE,
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   DOUBLE PRECISION NOT NULL,
      expires_at   DOUBLE PRECISION,
      revoked      INTEGER NOT NULL DEFAULT 0
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_share_links_goal ON share_links(goal_id);",
    """
    CREATE TABLE IF NOT EXISTS signoffs (
      goal_id    INTEGER PRIMARY KEY REFERENCES goals(id),
      decision   TEXT NOT NULL,
      decided_by TEXT NOT NULL DEFAULT '',
      note       TEXT,
      created_at DOUBLE PRECISION NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS goal_origins (
      goal_id    INTEGER PRIMARY KEY REFERENCES goals(id),
      kind       TEXT NOT NULL,
      ref        TEXT NOT NULL,
      created_at DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_goal_origins_ref ON goal_origins(kind, ref);",
]


# --- Temporal fact history (migration v18) -----------------------------------
# Parity with the SQLite bitemporal fact_history: `facts` keeps the single
# CURRENT value (UNIQUE key); this records each value's validity window so "what
# did we believe on date X, and why" is answerable -- non-destructive evolution
# instead of overwrite. Only written when [memory] temporal is enabled. `value`
# is sealed at rest like facts.value (reusing the shared field codec); the
# window/provenance columns stay plaintext so they remain queryable under
# encryption. tenant_id scopes it like every other table.
_FACT_HISTORY_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS fact_history (
      id                SERIAL PRIMARY KEY,
      key               TEXT NOT NULL,
      value             TEXT NOT NULL,
      source_episode_id INTEGER,
      valid_from        DOUBLE PRECISION NOT NULL,
      valid_to          DOUBLE PRECISION,
      source            TEXT NOT NULL DEFAULT '',
      trust_tier        INTEGER NOT NULL DEFAULT 3,
      sensitivity       TEXT NOT NULL DEFAULT 'internal',
      tenant_id         TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_fact_history_key "
    "ON fact_history (COALESCE(tenant_id, ''), key, valid_from);",
]


# --- Shared rate-limit events (migration v19) --------------------------------
# A cross-replica sliding-window counter for the dashboard's goal-creation rate
# limit. The dashboard's in-process limiter can't hold across replicas (N
# replicas allow N x the cap); on Postgres (the HA backend) the limiter records
# one row per admitted goal here and counts rows inside the window so every
# replica shares one ceiling. ``rl_key`` is the per-client/global bucket; rows
# are pruned past the window. Append-only and tiny; not tenant-scoped (the
# bucket key already encodes principal/source).
_RATE_EVENTS_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS rate_events (
      id      BIGSERIAL PRIMARY KEY,
      rl_key  TEXT NOT NULL,
      ts      DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_rate_events_key_ts ON rate_events (rl_key, ts);",
]


# v21 N-of-M dual control: quorum + requester columns on approvals, and the
# per-(approval, approver) signoff table. Mirrors the SQLite v21 migration.
_DUAL_CONTROL_MIGRATION: list[str] = [
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approvals_required "
    "INTEGER NOT NULL DEFAULT 1;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS requested_by TEXT;",
    """
    CREATE TABLE IF NOT EXISTS approval_signoffs (
      approval_id INTEGER NOT NULL,
      approver    TEXT NOT NULL,
      decision    TEXT NOT NULL,
      decided_at  DOUBLE PRECISION NOT NULL,
      note        TEXT,
      PRIMARY KEY (approval_id, approver)
    );
    """,
]


# v22 cluster-wide killswitch: an untenanted single-row global halt the
# dashboard arms and every replica's killswitch consults (shared-Postgres
# deployments). Not RLS-scoped on purpose -- a global emergency stop is not
# per-tenant.
_HALT_MIGRATION = [
    "CREATE TABLE IF NOT EXISTS halt ("
    " scope TEXT PRIMARY KEY, reason TEXT, source TEXT, armed_by TEXT,"
    " armed_at DOUBLE PRECISION NOT NULL)",
]

# v23 cluster-wide provider spend ledger: one authoritative per-(period,
# provider) total so provider_cost_cap's ceiling holds across the fleet. Not
# tenant-scoped -- a provider cap is a deployment-wide spend ceiling.
_PROVIDER_SPEND_MIGRATION = [
    "CREATE TABLE IF NOT EXISTS provider_spend ("
    " period_key TEXT NOT NULL, provider TEXT NOT NULL,"
    " dollars DOUBLE PRECISION NOT NULL DEFAULT 0,"
    " PRIMARY KEY (period_key, provider))",
]

# v24 facts provenance columns: persist source / trust_tier / sensitivity on the
# live `facts` table (same defaults as fact_history) so memory_guard reads the
# real recall-trust tier directly from `facts` -- closing the non-temporal
# fallback that defaulted every fact to tier 3. SQLite already carries these in
# its base CREATE (backfilled by its own v17); Postgres adds them here. Additive
# ADD COLUMN IF NOT EXISTS -- passes the migration-governance additive-only gate.
_FACTS_TRUST_MIGRATION: list[str] = [
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS trust_tier INTEGER NOT NULL DEFAULT 3;",
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS sensitivity TEXT NOT NULL DEFAULT 'internal';",
]

# v25 fleet learning store: the self-harness learning stores as shared tables so a multi-host fleet
# learns as one. Additive CREATE IF NOT EXISTS -- passes the
# migration-governance additive-only gate.
_HARNESS_STORE_MIGRATION: list[str] = [
    "CREATE TABLE IF NOT EXISTS harness_addenda ("
    " key TEXT PRIMARY KEY, block TEXT NOT NULL,"
    " updated_at DOUBLE PRECISION NOT NULL);",
    "CREATE TABLE IF NOT EXISTS harness_line_meta ("
    " line_id TEXT PRIMARY KEY, record TEXT NOT NULL,"
    " updated_at DOUBLE PRECISION NOT NULL);",
    "CREATE TABLE IF NOT EXISTS harness_transfer_tried ("
    " line_id TEXT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL);",
]

# v26 fleet learning store eval corpus: the eval-corpus family as shared rows
# (live/pending/rejected + "extra" preserving non-list top-level entries).
# Additive CREATE IF NOT EXISTS -- passes the additive-only gate.
_HARNESS_CORPUS_MIGRATION: list[str] = [
    "CREATE TABLE IF NOT EXISTS harness_corpus ("
    " kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL,"
    " row TEXT NOT NULL, PRIMARY KEY (kind, key, seq));",
]

# v27: cache-token spend columns (see world_model.MIGRATIONS[27]).
_EPISODE_CACHE_TOKENS_MIGRATION = [
    "ALTER TABLE episodes ADD COLUMN IF NOT EXISTS cache_read_tokens INTEGER DEFAULT 0;",
    "ALTER TABLE episodes ADD COLUMN IF NOT EXISTS cache_write_tokens INTEGER DEFAULT 0;",
]

# v28: per-principal goal ownership. SQLite has carried ``goals.owner`` since
# v11; Postgres previously exposed only tenant isolation, so authenticated
# callers of owner-scoped episode reads could not get SQLite-equivalent results.
# The empty default preserves legacy/admin semantics for every existing row.
_GOAL_OWNER_MIGRATION = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';",
]

# v29: tenant-scoped, insert-only erasure scope receipts. The signed manifest
# contains exact pre-delete row IDs but no raw subject or subject-derived hash.
# UPDATE is forbidden at the database layer; DELETE remains available only to
# the explicit retention/retirement path after ``retained_until``.
_ERASURE_RECEIPTS_MIGRATION = [
    """
    CREATE TABLE IF NOT EXISTS erasure_receipts (
      receipt_id     TEXT NOT NULL,
      tenant_id      TEXT NOT NULL,
      manifest       TEXT NOT NULL,
      created_at     DOUBLE PRECISION NOT NULL,
      retained_until DOUBLE PRECISION NOT NULL,
      PRIMARY KEY (tenant_id, receipt_id)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_erasure_receipts_retention "
    "ON erasure_receipts(tenant_id, retained_until);",
    """
    CREATE OR REPLACE FUNCTION mvk_erasure_receipts_no_update()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'erasure receipts are immutable';
    END;
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'erasure_receipts_no_update'
          AND tgrelid = 'erasure_receipts'::regclass
      ) THEN
        CREATE TRIGGER erasure_receipts_no_update
        BEFORE UPDATE ON erasure_receipts
        FOR EACH ROW EXECUTE FUNCTION mvk_erasure_receipts_no_update();
      END IF;
    END;
    $$;
    """,
    """
    CREATE OR REPLACE FUNCTION mvk_erasure_receipts_no_early_delete()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.retained_until > EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) THEN
        RAISE EXCEPTION 'erasure receipt retention is active';
      END IF;
      RETURN OLD;
    END;
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'erasure_receipts_no_early_delete'
          AND tgrelid = 'erasure_receipts'::regclass
      ) THEN
        CREATE TRIGGER erasure_receipts_no_early_delete
        BEFORE DELETE ON erasure_receipts
        FOR EACH ROW EXECUTE FUNCTION mvk_erasure_receipts_no_early_delete();
      END IF;
    END;
    $$;
    """,
]

# v30 approval/audit atomicity: a vote and its audit-delivery intent commit
# together. The final outcome remains pending until all queued vote events are
# durably appended to the signed audit chain.
_APPROVAL_AUDIT_OUTBOX_MIGRATION = [
    """
    CREATE TABLE IF NOT EXISTS approval_audit_outbox (
      event_id     TEXT PRIMARY KEY,
      approval_id  INTEGER NOT NULL REFERENCES approvals(id),
      status       TEXT NOT NULL,
      decided_by   TEXT NOT NULL,
      final_status TEXT,
      created_at   DOUBLE PRECISION NOT NULL,
      delivered_at DOUBLE PRECISION,
      tenant_id    TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_approval_audit_outbox_pending "
    "ON approval_audit_outbox(tenant_id, delivered_at, approval_id);",
]

# v31: a dedicated 64-bit logical write clock for fact recall ordering.
# Conflicting inserts reuse the one sequence value already materialized in
# EXCLUDED.write_seq, avoiding both 32-bit SERIAL exhaustion and primary-key
# churn on every reassertion.
_FACT_WRITE_SEQUENCE_MIGRATION = [
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS write_seq BIGSERIAL;",
    "CREATE INDEX IF NOT EXISTS idx_pg_facts_write_seq "
    "ON facts(write_seq DESC);",
]

# v32: keep the dashboard/resource owner distinct from the authority that
# executes the goal. The empty default lets the first legitimate dispatcher
# bind legacy rows atomically.
_GOAL_EXECUTION_PRINCIPAL_MIGRATION = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS execution_principal "
    "TEXT NOT NULL DEFAULT '';",
]

# v33: compare-and-delete token for the shared emergency stop.  Every arm
# rotates the token, so an older clear cannot delete a concurrently re-armed
# row.
_HALT_GENERATION_MIGRATION = [
    "ALTER TABLE halt ADD COLUMN IF NOT EXISTS generation "
    "TEXT NOT NULL DEFAULT '';",
]

MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, SCHEMA),
    (10, _TENANT_MIGRATION),
    (11, _TENANT_UNIQUE_MIGRATION),
    (13, _APPROVAL_CLAIMS_MIGRATION),
    (14, _GOAL_DOMAIN_MIGRATION),
    (15, _PROJECTS_MIGRATION),
    (16, _ARTIFACTS_MIGRATION),
    (17, _SHARE_SIGNOFF_ORIGIN_MIGRATION),
    (18, _FACT_HISTORY_MIGRATION),
    (19, _RATE_EVENTS_MIGRATION),
    (21, _DUAL_CONTROL_MIGRATION),
    (22, _HALT_MIGRATION),
    (23, _PROVIDER_SPEND_MIGRATION),
    (24, _FACTS_TRUST_MIGRATION),
    (25, _HARNESS_STORE_MIGRATION),
    (26, _HARNESS_CORPUS_MIGRATION),
    (27, _EPISODE_CACHE_TOKENS_MIGRATION),
    (28, _GOAL_OWNER_MIGRATION),
    (29, _ERASURE_RECEIPTS_MIGRATION),
    (30, _APPROVAL_AUDIT_OUTBOX_MIGRATION),
    (31, _FACT_WRITE_SEQUENCE_MIGRATION),
    (32, _GOAL_EXECUTION_PRINCIPAL_MIGRATION),
    (33, _HALT_GENERATION_MIGRATION),
    (34, [
        "CREATE TABLE IF NOT EXISTS provider_cap_receipts ("
        " period_key TEXT NOT NULL, provider TEXT NOT NULL,"
        " receipts_json TEXT NOT NULL, PRIMARY KEY (period_key, provider))",
    ]),
    (35, [
        "CREATE TABLE IF NOT EXISTS provider_operation_attempts ("
        " scope_sha256 TEXT NOT NULL, operation_id TEXT NOT NULL,"
        " attempt_no BIGINT NOT NULL, category TEXT NOT NULL,"
        " parent_category TEXT NOT NULL, service TEXT, provider TEXT NOT NULL,"
        " period_key TEXT NOT NULL, request_id TEXT NOT NULL,"
        " PRIMARY KEY (scope_sha256, operation_id, attempt_no),"
        " UNIQUE (provider, period_key, request_id))",
        "CREATE TABLE IF NOT EXISTS provider_operation_attempt_backfill ("
        " singleton SMALLINT PRIMARY KEY CHECK(singleton = 1),"
        " completed BOOLEAN NOT NULL CHECK(completed))",
    ]),
    (36, [
        "ALTER TABLE goals ADD COLUMN IF NOT EXISTS completed_at DOUBLE PRECISION",
        "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS goal_id INTEGER",
        "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS department TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_domain_completed "
        "ON goals(tenant_id, domain, completed_at)",
    ]),
    (37, [
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_root_owner "
        "ON goals(tenant_id, owner, id DESC) WHERE parent_id IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_root_shared_owner "
        "ON goals(owner, id DESC) WHERE parent_id IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_root_id "
        "ON goals(id DESC) WHERE parent_id IS NULL",
    ]),
    (38, [_ATTACHMENT_SUBMISSION_SCHEMA]),
    (39, LEARNING_TENANT_MIGRATION),
    (40, [_EVENT_ADMISSION_SCHEMA]),
    (41, [
        "ALTER TABLE event_goal_admissions ADD COLUMN IF NOT EXISTS request_digest TEXT",
        "ALTER TABLE event_goal_admissions ADD COLUMN IF NOT EXISTS sealed_contract TEXT",
        "CREATE INDEX IF NOT EXISTS idx_pg_event_admission_goal ON event_goal_admissions(tenant_id,goal_id)",
    ]),
]

MIGRATIONS.append((42, [_GOAL_MUTATION_SCHEMA]))
MIGRATIONS.append((43, ["ALTER TABLE facts ADD COLUMN IF NOT EXISTS tags_json TEXT NOT NULL DEFAULT '[]'"]))

# Highest migration version = the reported schema version.
MIGRATIONS.append((44, _PERSONAL_ALERT_MIGRATION))
MIGRATIONS.append((45, _HISTORY_INDEXES))
MIGRATIONS.append((46, ["ALTER TABLE goals ADD COLUMN IF NOT EXISTS connection_selection TEXT NOT NULL DEFAULT ''"]))
MIGRATIONS.append((47, [
    # The teardown draft assigned v42 to webhook/alert tables. Its existing
    # databases can therefore lack the companion draft's v42 receipt table.
    # Idempotently ensure both draft additions without rewriting v42..v46.
    _GOAL_MUTATION_SCHEMA,
    *_WEBHOOK_SUBSCRIPTION_SCHEMA_PG,
    *_DEADLINE_ALERT_SCHEMA_PG,
]))
# v48: approval-gate decisions without content (maverick.approval_checks).
MIGRATIONS.append((48, _APPROVAL_CHECK_SCHEMA_PG))

# v49: retire only the unused ciphertext-derived message-search index.
# The authoritative messages table, its contents and tenant policies remain.
MIGRATIONS.append((49, ["DROP INDEX IF EXISTS idx_pg_messages_fts"]))

# Questions inherit tenant scope through their goal; keep that guarded join.
MIGRATIONS.append((50, ["CREATE INDEX IF NOT EXISTS idx_pg_questions_goal_id ON questions(goal_id, id)"]))

# v51: which decisions can still be undone (mirrors SQLite v51).
MIGRATIONS.append((51, ["ALTER TABLE approvals ADD COLUMN IF NOT EXISTS undo_hold TEXT"]))

# v52: completion is tenant-scoped so RLS-hidden rows are never certified.
MIGRATIONS.append((52, [
    "CREATE TABLE IF NOT EXISTS encryption_migrations ("
    "scope TEXT PRIMARY KEY, tenant_id TEXT, migrated_at DOUBLE PRECISION NOT NULL, "
    "CHECK (scope = CASE WHEN tenant_id IS NULL THEN 'n:' ELSE 't:' || tenant_id END))",
]))

# v53: an external agent's run report key binds one goal (mirrors SQLite v53).
MIGRATIONS.append((53, [
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_pg_goal_origins_external_run "
    "ON goal_origins(ref) WHERE kind = 'external_run'",
]))

# v54: heartbeats get their own liveness timestamp (mirrors SQLite v54).
MIGRATIONS.append((54, ["ALTER TABLE goals ADD COLUMN IF NOT EXISTS heartbeat_at DOUBLE PRECISION"]))

# v55: decision requests, scoped through their goal like questions (mirrors SQLite v55).
MIGRATIONS.append((55, _DECISION_REQUEST_SCHEMA_PG))

# v56: row policies for every table that holds a workspace's records.
# Events and episodes get a ``tenant_id`` copy of their goal's, kept in step
# by triggers from here on. The column has no default, so adding it is cheap;
# filling it for existing rows rewrites every row, so that happens only where
# row-level security is on. A database that already forces it on ``goals``
# is filled here, in this transaction (with that FORCE lifted for the fill),
# and the tables that had no policy get one. Elsewhere nothing is rewritten:
# turning row-level security on later fills the copy in short batches
# (``_fill_stamped_tenants``) before ``_apply_rls`` installs any policy.
# Run by the table owner.
_V56_RLS_TABLES = ("approval_checks", *_RLS_RAW_TENANT_TABLES, *_RLS_STAMPED_TABLES,
                   *_RLS_CHILD_TABLES)
_V56_FORCED = ("EXISTS (SELECT 1 FROM pg_class WHERE oid = 'goals'::regclass "
               "AND relrowsecurity AND relforcerowsecurity)")
MIGRATIONS.append((56, [
    *(f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS tenant_id TEXT" for t in _RLS_STAMPED_TABLES),
    f"DO $$ BEGIN IF {_V56_FORCED} THEN "
    "ALTER TABLE goals NO FORCE ROW LEVEL SECURITY; "
    + "".join(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY; UPDATE {t} c SET tenant_id = g.tenant_id FROM goals g WHERE g.id = c.goal_id "
              "AND c.tenant_id IS DISTINCT FROM g.tenant_id; "
              f"CREATE INDEX IF NOT EXISTS idx_pg_{t}_tenant ON {t}(tenant_id); "
              f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY; "
              for t in _RLS_STAMPED_TABLES)
    + "ALTER TABLE goals FORCE ROW LEVEL SECURITY; END IF; END $$",
    "CREATE OR REPLACE FUNCTION mvk_stamp_goal_tenant() RETURNS trigger LANGUAGE plpgsql AS $$ "
    "BEGIN NEW.tenant_id := (SELECT g.tenant_id FROM goals g WHERE g.id = NEW.goal_id); "
    "RETURN NEW; END; $$",
    "CREATE OR REPLACE FUNCTION mvk_goal_tenant_follows() RETURNS trigger LANGUAGE plpgsql AS $$ "
    "BEGIN "
    + "".join(f"UPDATE {t} SET tenant_id = NEW.tenant_id WHERE goal_id = NEW.id; "
              for t in _RLS_STAMPED_TABLES)
    + "RETURN NULL; END; $$",
    *(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '{t}_goal_tenant' "
      f"AND tgrelid = '{t}'::regclass) THEN CREATE TRIGGER {t}_goal_tenant "
      f"BEFORE INSERT OR UPDATE OF goal_id, tenant_id ON {t} FOR EACH ROW "
      "EXECUTE FUNCTION mvk_stamp_goal_tenant(); END IF; END $$" for t in _RLS_STAMPED_TABLES),
    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'goals_tenant_follows' "
    "AND tgrelid = 'goals'::regclass) THEN CREATE TRIGGER goals_tenant_follows "
    "AFTER UPDATE OF tenant_id ON goals FOR EACH ROW "
    "WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id) "
    "EXECUTE FUNCTION mvk_goal_tenant_follows(); END IF; END $$",
    *(f"DO $$ BEGIN IF {_V56_FORCED} "
      f"AND NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = '{table}'::regclass "
      "AND polname = 'mvk_tenant_isolation') THEN "
      f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; "
      f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
      f"{_rls_policy_statement(table)}; "
      "END IF; END $$"
      for table in _V56_RLS_TABLES),
]))
#: Rows of an event or episode table filled per transaction when row-level
#: security is turned on (``PostgresWorldModel._fill_stamped_tenants``).
_STAMP_FILL_BATCH = 10_000
#: Tries per fill batch when the tables stay busy for longer than 200 ms.
_STAMP_FILL_ATTEMPTS = 5

_PG_SCHEMA_VERSION = MIGRATIONS[-1][0]

_MIGRATIONS_TABLE = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "  version    INTEGER PRIMARY KEY,"
    "  applied_at DOUBLE PRECISION NOT NULL"
    ");"
)

# Transaction-scoped advisory lock serializing schema migration across replicas.
# Postgres CREATE TABLE/INDEX ... IF NOT EXISTS is NOT concurrency-safe (two
# replicas running it at once can raise "tuple concurrently updated" /
# duplicate-key on the catalog), so concurrent startup of an HA fleet could fail
# or partially-migrate. Holding this lock makes the second replica wait, then
# re-read the version and find nothing to do. Arbitrary fixed key (auto-released
# at COMMIT/ROLLBACK).
_MIGRATION_ADVISORY_LOCK = 0x6D766B6D6967  # 'mvkmig'


def pending_migrations(
    current_version: int,
    migrations: list[tuple[int, list[str]]] | None = None,
) -> list[tuple[int, list[str]]]:
    """Migrations with ``version > current_version``, in ascending order.

    Pure planner (no DB) so the upgrade logic is unit-tested directly.
    """
    migs = MIGRATIONS if migrations is None else migrations
    return [(v, stmts) for v, stmts in sorted(migs) if v > current_version]


def _active_tenant() -> str | None:
    """The tenant scoping this call, or ``None`` for the legacy single-tenant
    store. Lazy import keeps this module free of a hard ``paths`` dependency."""
    # Resolution failures are not equivalent to deliberately unbound legacy
    # mode: swallowing one here removes every app-layer tenant predicate.
    from ..paths import current_tenant_strict
    return current_tenant_strict()


def _active_workspace() -> str | None:
    """The raw tenant id the ``workspace`` columns are written with, or ``None``
    when unbound. It must be exactly ``webhook_subscriptions.workspace_id()``:
    the RLS policy on those tables compares the column with this value."""
    from ..paths import current_tenant_id_strict
    return current_tenant_id_strict()


class DatabaseUpgradeNeedsOwner(RuntimeError):
    """A pending migration this login may not apply: it does not own the
    tables. Doctor, the dashboard error page and readiness say this text."""

    def __init__(self, version: int) -> None:
        super().__init__(
            f"Second Shift needs to update its Postgres database to version {version}. "
            "This database login does not own the tables, so nothing was changed. "
            "Start Second Shift once as the owner of the tables, then start it again "
            "with this login.")


def bind_rls_scope(cur) -> None:
    """Bind the open transaction on ``cur`` to the active workspace for the
    row policies. With no workspace active, an impossible sentinel matches
    no row."""
    tenant = _active_tenant()
    value = str(tenant) if tenant is not None else "__maverick_no_tenant__"
    # The workspace-keyed tables store the raw id, which differs from the
    # encoded segment for an id such as ``slack:U1``; both are bound in the
    # same statement so neither can be left over from an earlier scope.
    workspace = _active_workspace() if tenant is not None else None
    raw = str(workspace) if workspace else "__maverick_no_tenant__"
    # set_config(name, value, is_local=true) is the parameterizable form of
    # SET LOCAL — transaction-scoped, cleared at commit/rollback.
    cur.execute(
        "SELECT set_config('maverick.tenant', %s, true), "
        "set_config('maverick.workspace', %s, true)",
        (value, raw),
    )


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _explicit_toggle(env_var: str, cfg_key: str) -> bool | None:
    """Resolve an explicitly-set tenant-isolation toggle, or ``None`` if unset.

    Env (``env_var``) wins over ``[world_model] <cfg_key>`` config. Returns
    ``None`` only when neither the env var nor the config key is present, so the
    caller can distinguish "operator chose off" from "operator said nothing" --
    the distinction the enterprise auto-on + boot preflight rely on.
    """
    env = os.environ.get(env_var)
    if env is not None and env.strip() != "":
        return _truthy(env)
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("world_model") or {}
    except Exception:  # pragma: no cover -- config never blocks construction
        return None
    if cfg_key in cfg:
        v = cfg.get(cfg_key)
        return _truthy(v) if isinstance(v, str) else bool(v)
    return None


def _enterprise_default() -> bool:
    """Enterprise mode auto-enables tenant isolation (off otherwise).

    Lazy + defensive: a missing/raising enterprise module never blocks
    construction of a single-tenant store, it just means "not enterprise".
    """
    try:
        from ..enterprise import enterprise_enabled
        return bool(enterprise_enabled())
    except Exception:  # pragma: no cover -- enterprise never blocks construction
        return False


def _strict_tenant_isolation() -> bool:
    """Strict per-tenant reads. When on, a tenant sees **only** its own rows --
    legacy ``NULL`` rows are no longer visible; safe only after the legacy rows
    have been backfilled with a tenant_id.

    Resolution: ``MAVERICK_STRICT_TENANT_ISOLATION`` env wins over
    ``[world_model] strict_tenant_isolation`` config, which wins over enterprise
    mode (auto-on). Off for the default single-tenant install."""
    explicit = _explicit_toggle("MAVERICK_STRICT_TENANT_ISOLATION", "strict_tenant_isolation")
    if explicit is not None:
        return explicit
    return _enterprise_default()


def _rls_enabled() -> bool:
    """DB-native Row-Level Security. When on, the tenant-scoped tables get a
    Postgres RLS policy keyed on the ``maverick.tenant`` session GUC, so the
    database enforces the tenant boundary even if an app-layer predicate is ever
    missed — defense in depth over ``_tenant_scope``. Implies the legacy
    ``NULL`` rows have been backfilled (RLS scopes strictly to the active
    tenant), which is why enterprise auto-on is gated by a boot preflight.

    Resolution: ``MAVERICK_PG_RLS`` env wins over ``[world_model] rls`` config,
    which wins over enterprise mode (auto-on). Off otherwise."""
    explicit = _explicit_toggle("MAVERICK_PG_RLS", "rls")
    if explicit is not None:
        return explicit
    return _enterprise_default()


def _rls_explicitly_set() -> bool:
    """True when the operator explicitly chose the RLS toggle (env or config).

    The boot preflight only *refuses* to start on legacy ``NULL`` rows when RLS
    was auto-enabled by enterprise mode; an operator who set ``MAVERICK_PG_RLS=1``
    has opted into the strict boundary knowingly, so we keep the existing
    fail-closed install path for them rather than blocking boot."""
    return _explicit_toggle("MAVERICK_PG_RLS", "rls") is not None


def _configured_dsn() -> str:
    """``[world_model] dsn`` (config.toml or the dashboard settings, where it is
    kept sealed); ``MAVERICK_PG_DSN`` in the environment wins over it."""
    try:
        from ..config import load_config
        value = ((load_config() or {}).get("world_model") or {}).get("dsn")
    except Exception:  # pragma: no cover -- config never blocks construction
        return ""
    return str(value).strip() if isinstance(value, str) else ""


def _pool_size() -> int:
    """Max connections for the optional ``psycopg_pool`` connection pool
    (default 0 = no pool, single shared connection as before). A positive value
    opts into pooled mode for horizontal scale under concurrent load.
    ``MAVERICK_PG_POOL_SIZE`` env wins over ``[world_model] pool_size``."""
    raw = os.environ.get("MAVERICK_PG_POOL_SIZE")
    if raw is None or raw.strip() == "":
        try:
            from ..config import load_config
            raw = (load_config() or {}).get("world_model", {}).get("pool_size")
        except Exception:  # pragma: no cover -- config never blocks construction
            raw = None
    try:
        return max(0, int(raw)) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


def _to_pg_paramstyle(sql: str) -> str:
    """Rewrite a SQLite-paramstyle statement for psycopg.

    ``?`` placeholders outside single-quoted literals become ``%s``; every
    literal ``%`` (``LIKE 'agent:%'``) is doubled, because psycopg treats ``%``
    as the placeholder marker whenever parameters are passed -- inside string
    literals too.
    """
    out: list[str] = []
    in_literal = False
    for ch in sql:
        if ch == "'":
            in_literal = not in_literal
            out.append(ch)
        elif ch == "%":
            out.append("%%")
        elif ch == "?" and not in_literal:
            out.append("%s")
        else:
            out.append(ch)
    return "".join(out)


class _PgRow(tuple):
    """A psycopg tuple row that also answers ``row["column"]``.

    ``WorldModel.query`` returns ``sqlite3.Row`` objects, which support index,
    key and unpacking; this keeps the Postgres side interchangeable without
    switching the shared connection's row factory.
    """

    _columns: dict[str, int]

    @classmethod
    def wrap(cls, row: tuple, columns: dict[str, int]) -> _PgRow:
        obj = cls(row)
        obj._columns = columns
        return obj

    def __getitem__(self, key):  # type: ignore[override]
        if isinstance(key, str):
            return tuple.__getitem__(self, self._columns[key])
        return tuple.__getitem__(self, key)

    def keys(self) -> list[str]:
        return list(self._columns)


def _tenant_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Read predicate scoping rows to the active tenant.

    Returns ``(sql_fragment, params)``. With **no** active tenant, only legacy
    unbound rows are visible, preserving single-tenant data without exposing
    named workspaces. With a tenant set,
    the default (NULL-tolerant) predicate matches that tenant's rows **plus**
    legacy ``NULL`` rows; strict mode (``[world_model] strict_tenant_isolation``)
    matches **only** that tenant's rows, the RLS-equivalent hard boundary.
    """
    t = _active_tenant()
    if t is None:
        return f"{column} IS NULL", []
    if _strict_tenant_isolation():
        return f"{column} = %s", [t]
    return f"({column} = %s OR {column} IS NULL)", [t]


def _approval_outbox_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Exact tenant predicate for newly stamped approval-audit rows.

    Unlike compatibility reads of legacy root tables, an active tenant must
    never inherit a legacy/null outbox event. Every v30 write has an explicit
    tenant value (or deliberately unbound ``NULL`` in legacy single-tenant
    mode), so exact matching is both safe and lossless.
    """
    tenant = _active_tenant()
    if tenant is None:
        return f"{column} IS NULL", []
    return f"{column} = %s", [tenant]


def _mutation_tenant_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Exact tenant predicate for ordinary writes and deletes.

    ``_tenant_scope`` may expose legacy NULL rows to compatibility reads.
    That behavior does not grant mutation authority: unbound callers may change
    only legacy NULL rows, and bound callers may change only their exact
    tenant. Legacy ownership must be assigned explicitly before mutation.
    """
    tenant = _active_tenant()
    if tenant is None:
        return f"{column} IS NULL", []
    return f"{column} = %s", [tenant]


@dataclass
class PGGoal:
    """Mirror of maverick.world_model.Goal — same fields for drop-in compat."""
    id: int
    parent_id: int | None
    title: str
    description: str | None
    status: str
    created_at: float
    updated_at: float
    deadline: float | None
    result: str | None
    owner: str = ""
    execution_principal: str = ""
    domain: str = ""
    project_id: int | None = None


def _seal(text, context=None):
    """Seal a sensitive text column for storage (no-op when at-rest is off).

    Reuses the SQLite backend's field codec so the on-disk format and the
    fail-closed semantics are identical across backends. ``context`` is the
    destination ``table.column``; the value is bound to it and to the tenant."""
    from ..world_model import _enc_field
    return _enc_field(text, context, bind_tenant=True)


def _legacy_of(table: str, id_column: str) -> str:
    """SQL for "the row of ``table`` that ``id_column`` names has no tenant".

    Child tables (goal_events, artifacts, questions, episodes, signoffs,
    turns) carry no tenant column; their tenant is the parent's. Selected next
    to sealed columns so reads can apply :func:`_unseal`'s ``legacy_row``."""
    return (f"COALESCE((SELECT lp.tenant_id IS NULL FROM {table} lp "
            f"WHERE lp.id = {id_column}), FALSE)")


def _unseal(text, context=None, *, legacy_row=False):
    """Inverse of :func:`_seal` (no-op when at-rest is off; legacy plaintext and
    strict-mode handling identical to the SQLite backend). A value bound to
    another column than ``context`` is withheld.

    ``legacy_row`` marks a row whose own tenant column (or its parent's, for
    a child table) is NULL. An unbound caller sealed it, so it first opens with
    the empty tenant binding, as a SQLite world opens from any context; a
    value the active tenant wrote into such a row still opens with its own
    binding. A token bound to any other tenant fails both. Visibility stays
    with the caller's tenant scope, and write paths keep exact-tenant scope,
    so they never see a legacy row under a tenant."""
    from ..world_model import _dec_field
    if legacy_row:
        value = _open_unbound(text, context)
        if value is not None:
            return value
    return _dec_field(text, context=context)


def _open_unbound(text, context):
    """A legacy value opened with the empty tenant binding, or None when that
    binding does not open it (withheld or raised) or there is no tenant to
    differ from: the caller then reads it the ordinary way."""
    from ..crypto_at_rest import EncryptionUnavailable, unbound_row_scope
    from ..world_model import _UNSEALED_WITHHELD, _dec_field
    if _active_tenant() is None:
        return None
    try:
        with unbound_row_scope():
            value = _dec_field(text, context=context)
    except EncryptionUnavailable:
        return None
    return None if value == _UNSEALED_WITHHELD else value


def _dec_goal_row(row) -> PGGoal:
    """Build a PGGoal from a row, unsealing the at-rest-encrypted text columns
    (title / description / result). Reuses the SQLite backend's field codec so
    sealing semantics (legacy-plaintext passthrough, strict-mode withhold) are
    identical across backends. No-op when at-rest encryption is off. Column 13,
    when selected, is ``tenant_id IS NULL`` (see :func:`_unseal`)."""
    legacy = len(row) > 13 and bool(row[13])
    return _goal_from_decoded_row(row, _unseal(row[2], "goals.title", legacy_row=legacy),
                                  _unseal(row[3], "goals.description", legacy_row=legacy),
                                  _unseal(row[8], "goals.result", legacy_row=legacy))


def _goal_from_decoded_row(row, title, description, result) -> PGGoal:
    return PGGoal(
        row[0], row[1], title, description, row[4],
        row[5], row[6], row[7], result,
        str(row[9] or "") if len(row) > 9 else "",
        str(row[10] or "") if len(row) > 10 else "",
        str(row[11] or "") if len(row) > 11 else "",
        (int(row[12]) if row[12] is not None else None) if len(row) > 12 else None,
    )


def _dec_approval_row(r):
    """Build an Approval, unsealing action/scope/detail (provenance is trusted
    plaintext metadata, sealed neither here nor in SQLite). Row order: id,
    action, risk, scope, detail, provenance, status, requested_at, decided_at,
    claimed_by, claimed_at, decided_by, approvals_required, requested_by,
    goal_id, department, undo_hold, and optionally tenant_id IS NULL."""
    from ..world_records import Approval
    legacy = len(r) > 17 and bool(r[17])
    return Approval(r[0], _unseal(r[1], "approvals.action", legacy_row=legacy), r[2],
                    _unseal(r[3], "approvals.scope", legacy_row=legacy),
                    _unseal(r[4], "approvals.detail", legacy_row=legacy),
                    r[5], r[6], r[7], r[8], r[9], r[10], r[11],
                    int(r[12]) if len(r) > 12 and r[12] is not None else 1,
                    r[13] if len(r) > 13 else None,
                    r[14] if len(r) > 14 else None,
                    r[15] if len(r) > 15 else "",
                    r[16] if len(r) > 16 else None)


def _dec_approval_audit_row(r):
    from ..world_records import ApprovalAuditEvent

    return ApprovalAuditEvent(
        event_id=str(r[0]),
        approval_id=int(r[1]),
        status=str(r[2]),
        decided_by=str(r[3]),
        final_status=str(r[4]) if r[4] is not None else None,
        created_at=float(r[5]),
        delivered_at=float(r[6]) if r[6] is not None else None,
    )


def _connection_kwargs(dsn: str) -> dict:
    """Preserve operator libpq options while bounding unattended transactions."""
    from ..db_timeouts import postgres_connection_kwargs

    return postgres_connection_kwargs(dsn)


class PostgresWorldModel:
    """Postgres adapter. Public surface mirrors SQLite WorldModel.

    Constructed lazily: importing psycopg only happens when the user
    actually configures the postgres backend.
    """

    # The SQLite backend exposes ``.path`` (its on-disk DB file); callers such
    # as the CLI progress poller and ``maverick monitor`` read it. There is no
    # local file for Postgres, and the DSN carries credentials so it must never
    # be surfaced as a path. ``None`` means "no pollable file" -- the poller
    # skips file-based streaming rather than raising AttributeError.
    path = None

    def __init__(self, dsn: str | None = None):
        try:
            import psycopg  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "psycopg not installed. Run: python -m pip install -e './packages/maverick-core[postgres]'"
            ) from e
        self._dsn = dsn or os.environ.get("MAVERICK_PG_DSN") or _configured_dsn()
        if not self._dsn:
            raise RuntimeError(
                "Postgres world model requires MAVERICK_PG_DSN or "
                "[world_model] dsn in config.toml."
            )
        # Startup transactions precede the marker table and RLS installation.
        self._posture_ready = False
        self._posture_identity = hashlib.sha256(self._dsn.encode()).hexdigest()
        from ..postgres_io import BoundedConnection, postgres_io_timeout_seconds

        self._rls = _rls_enabled()
        # Optional connection pool (opt-in via [world_model] pool_size). Pooled
        # mode hands each transaction its own connection from the pool, so the
        # backend scales across concurrent callers instead of serialising on one
        # shared connection. Default (pool_size 0) keeps the original
        # single-connection + RLock ownership model.
        self._pool = None
        size = _pool_size()
        # A statement timeout (QueryCanceled, an OperationalError) and a
        # terminated idle transaction both make _tx close the connection; the
        # next call reconnects. Retain these options on reconnect.
        self._io_timeout_seconds = postgres_io_timeout_seconds()
        self._connect_kwargs = _connection_kwargs(self._dsn)
        if size > 0:
            try:
                from psycopg_pool import ConnectionPool
            except ImportError as e:
                raise ImportError(
                    "[world_model] pool_size set but psycopg_pool is not "
                    "installed. Run: python -m pip install -e './packages/maverick-core[postgres]'"
                ) from e
            self._pool = ConnectionPool(
                self._dsn, min_size=1, max_size=size, open=True,
                connection_class=BoundedConnection,
                kwargs={**self._connect_kwargs, "io_timeout_seconds": self._io_timeout_seconds},
            )
            self.conn = None
        else:
            self.conn = BoundedConnection.connect(
                self._dsn, io_timeout_seconds=self._io_timeout_seconds, **self._connect_kwargs,
            )
        # One long-lived connection shared across this object (non-pooled mode).
        # psycopg connections are NOT safe for concurrent use by multiple
        # threads, and the kernel drives this from FastAPI's threadpool + the
        # background runner. Serialize every transaction the way the SQLite
        # WorldModel does with its RLock; without it, interleaved
        # execute/commit/rollback corrupt results or raise
        # InFailedSqlTransaction. (Reentrant so a method can nest _tx.) The pool
        # gives each tx its own connection, so the lock is a no-op contention
        # point there but harmless.
        self._lock = threading.RLock()
        self._tx_depth = threading.local()
        self.rls_bypass_reason: str | None = None
        # Set whether or not RLS is on: governed records refuse such a login.
        self.login_bypasses_rls: str | None = None
        try:
            self._check_database_role()
            self._migrate()
            if self._rls:
                self._preflight_rls_or_die()
                self._apply_rls()
            # The marker is read by the first transaction that follows, which
            # is before anything it fetched can be decrypted.
            self._posture_ready = True
        except BaseException:
            self.close()
            raise

    def _check_database_role(self) -> None:
        """Note, once per open, whether this login bypasses row-level security.

        A superuser or BYPASSRLS role skips every RLS policy, FORCE included.
        With RLS in use, enterprise mode refuses to open; otherwise the problem
        is logged once and reported by the deep health check. With RLS off no
        policy is bypassed, so it is only logged. A failed lookup is only
        logged, so an unreadable catalog never blocks boot.
        """
        try:
            with self._tx() as cur:
                cur.execute(
                    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
                )
                superuser, bypass = cur.fetchone()
        except Exception as e:
            log.warning(
                "Could not check whether the Postgres login bypasses row-level security "
                "(%s); tenant row policies are not verified at this start.", e,
            )
            return
        if not (superuser or bypass):
            return
        problem = (
            "the Postgres login is a superuser, which bypasses row-level security"
            if superuser
            else "the Postgres login has BYPASSRLS, which bypasses row-level security"
        )
        self.login_bypasses_rls = problem
        fix = (
            "connect with a dedicated login that is neither a superuser nor BYPASSRLS "
            "(for example CREATE ROLE maverick_app LOGIN NOSUPERUSER NOBYPASSRLS)"
        )
        if not self._rls:
            # No row policy is in use, so nothing is bypassed yet: a hint only.
            log.warning("%s. Turning on [world_model] rls would not protect tenants "
                        "for this login. Fix: %s.", problem, fix)
            return
        self.rls_bypass_reason = f"{problem}; {fix}"
        if _enterprise_default():
            raise RuntimeError(
                "Enterprise mode relies on Postgres row-level security for tenant "
                f"isolation, but {problem}. Fix: {fix}."
            )
        log.warning("%s. Tenant row policies do not apply to this login. Fix: %s.", problem, fix)

    def __enter__(self) -> PostgresWorldModel:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _reconnect_if_broken(self) -> None:
        """Reopen the single shared connection (non-pooled mode) after
        it's been killed out from under us.

        Managed Postgres (RDS/CloudSQL multi-AZ) fails over and resets idle
        connections; without this, the ``psycopg`` driver had already marked
        ``self.conn`` closed (from a PREVIOUS ``_tx()`` that caught the break
        and closed it -- see the ``except`` clause below) and every later
        call would raise ``OperationalError`` forever, turning a transient DB
        blip into an outage that needs a process restart. Only checks the
        cheap, local ``.closed`` flag -- it can't detect a connection the
        server killed but the client hasn't tried to use since; that case is
        caught where it actually surfaces, inside ``_tx``'s try block.
        """
        if self.conn is not None and not self.conn.closed:
            return
        from ..postgres_io import BoundedConnection

        self.conn = BoundedConnection.connect(
            self._dsn, io_timeout_seconds=self._io_timeout_seconds, **self._connect_kwargs,
        )

    @contextmanager
    def _tx(self, *, snapshot: bool = False) -> Iterator:
        """Cursor scope that commits on success and ROLLS BACK on error.

        Critical for autocommit=False: a single failed statement aborts
        the transaction, and without a rollback every later statement on
        this (shared, long-lived) connection fails with
        InFailedSqlTransaction until the process restarts. Rolling back
        keeps the connection usable.

        A rollback can't save a connection the SERVER killed (a
        managed-Postgres failover, or an idle-connection reset) -- the
        rollback itself fails too. In that case, close and drop the
        connection instead of leaving a dead one in ``self.conn``, so
        ``_reconnect_if_broken()`` opens a fresh one on the NEXT call rather
        than repeating ``OperationalError`` forever until the process
        restarts.

        A ``_tx`` opened while this thread already holds one joins it under a
        savepoint (see :meth:`_nested_tx`): it never commits the outer
        transaction early, nor waits for a second pooled connection.
        """
        if getattr(self._tx_depth, "value", 0):
            yield from self._nested_tx()
            return
        if self._pool is not None:
            # Pooled: each tx gets its own connection; the pool's context
            # commits on success and rolls back on error, so no shared lock.
            # psycopg_pool already detects and replaces a broken connection.
            with self._pool.connection() as conn:
                cur = conn.cursor()
                try:
                    if snapshot:
                        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    self._set_tenant_guc(cur)
                    self._note_encryption_posture(cur)
                    self._tx_depth.value, self._tx_depth.conn = 1, conn
                    self._tx_depth.scope = (_active_tenant(), _active_workspace())
                    try:
                        yield cur
                    finally:
                        self._tx_depth.value, self._tx_depth.conn = 0, None
                finally:
                    cur.close()
            return
        import psycopg
        with self._lock:
            self._reconnect_if_broken()
            cur = None
            try:
                cur = self.conn.cursor()
                if snapshot:
                    cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                self._set_tenant_guc(cur)
                self._note_encryption_posture(cur)
                self._tx_depth.value, self._tx_depth.conn = 1, self.conn
                self._tx_depth.scope = (_active_tenant(), _active_workspace())
                try:
                    yield cur
                finally:
                    self._tx_depth.value, self._tx_depth.conn = 0, None
                self.conn.commit()
            except (psycopg.OperationalError, psycopg.InterfaceError):
                try:
                    self.conn.close()
                except Exception:  # pragma: no cover
                    pass
                raise
            except Exception:
                try:
                    self.conn.rollback()
                except (psycopg.OperationalError, psycopg.InterfaceError):
                    try:
                        self.conn.close()
                    except Exception:  # pragma: no cover
                        pass
                except Exception:  # pragma: no cover
                    pass
                raise
            finally:
                if cur is not None:
                    cur.close()

    def _nested_tx(self) -> Iterator:
        """Run a nested ``_tx`` inside the transaction this thread holds.

        A savepoint confines an inner failure to the inner statements, so the
        outer transaction stays usable. The outer transaction's tenant binding
        (a transaction-local setting) and locks stay in force; a nested scope
        for another workspace is refused rather than re-binding the outer one.
        """
        if self._rls and self._tx_depth.scope != (_active_tenant(), _active_workspace()):
            raise RuntimeError("a nested world transaction cannot switch workspace")
        depth = self._tx_depth.value
        name = f"maverick_nested_{depth}"
        cur = self._tx_depth.conn.cursor()
        try:
            cur.execute(f"SAVEPOINT {name}")
            self._tx_depth.value = depth + 1
            try:
                yield cur
            except BaseException:
                with suppress(Exception):  # a dead connection fails the outer tx anyway
                    cur.execute(f"ROLLBACK TO SAVEPOINT {name}")
                raise
            finally:
                self._tx_depth.value = depth
            cur.execute(f"RELEASE SAVEPOINT {name}")
        finally:
            cur.close()

    def _note_encryption_posture(self, cur) -> None:
        if not getattr(self, "_posture_ready", False):
            return
        from ..encryption_migrate import postgres_migration_scope
        from ..world_model import _POSTGRES_STORE_POSTURES

        tenant = _active_tenant()
        if _POSTGRES_STORE_POSTURES.get((self._posture_identity, tenant)):
            return  # The marker is never removed, so a rebound tenant stays rebound.
        cur.execute("SELECT 1 FROM encryption_migrations WHERE scope=%s",
                    (postgres_migration_scope(tenant),))
        _POSTGRES_STORE_POSTURES[(self._posture_identity, tenant)] = cur.fetchone() is not None

    def _set_tenant_guc(self, cur) -> None:
        """Under RLS, bind this transaction to the active tenant.

        RLS is fail-closed: when no tenant is active, set an impossible sentinel
        instead of leaving the GUC unset. Queries that bypass ``_tx`` also fail
        closed because the policy does not grant access for unset/empty GUCs.
        """
        if not self._rls:
            return
        bind_rls_scope(cur)

    def _preflight_rls_or_die(self) -> None:
        """Refuse to boot when enterprise auto-on RLS would silently hide rows.

        When the operator explicitly enabled RLS (``MAVERICK_PG_RLS=1`` /
        ``[world_model] rls = true``) they have knowingly opted into the strict
        boundary, so we skip this gate and let ``_apply_rls`` install the
        fail-closed policy as before. But when RLS was *auto-enabled* by
        enterprise mode, forcing the policy on a store that still holds
        legacy ``tenant_id IS NULL`` rows would freeze those rows invisibly --
        data loss by side effect. So we run the read-only :func:`pg_rls.preflight`
        and raise with a remediation pointer instead of booting.

        Ownership problems are left to ``_apply_rls`` (it tolerates a non-owner
        connection when the policy is already installed); this gate is strictly
        about the NULL-tenant data-safety hazard.
        """
        if _rls_explicitly_set():
            return
        from . import pg_rls
        # A table whose policy is already installed and forced was gated on an
        # earlier boot; counting it again proves nothing (FORCE RLS with no
        # tenant shows zero rows) and only adds full scans that a statement
        # timeout can turn into a refusal to start.
        pending = tuple(
            t for t in pg_rls._PREFLIGHT_TABLES if not self._rls_policy_is_active(t)
        )
        if not pending:
            return
        try:
            if self._pool is not None:
                with self._pool.connection() as conn:
                    report = pg_rls.preflight(conn, only=pending)
            else:
                report = pg_rls.preflight(self.conn, only=pending)
        except Exception as e:
            # An explicit opt-in returned above, so this is the auto-on path the
            # gate protects: forcing the policy without knowing whether legacy
            # rows exist risks hiding and freezing them. Refuse to boot.
            raise RuntimeError(
                "Enterprise mode auto-enabled Postgres RLS, but the legacy-row "
                f"preflight could not run ({e}). Retry, or check with "
                "`maverick tenant rls-preflight`; to opt into RLS knowingly, set "
                "MAVERICK_PG_RLS=1 explicitly."
            ) from e
        offenders = {
            t: (info.get("null_tenant_rows") or 0) + (info.get("empty_tenant_rows") or 0)
            for t, info in report.get("tables", {}).items()
            if info.get("null_tenant_rows") or info.get("empty_tenant_rows")
        }
        if offenders:
            detail = ", ".join(f"{t}={n}" for t, n in sorted(offenders.items()))
            raise RuntimeError(
                "Enterprise mode auto-enabled Postgres RLS, but legacy rows with "
                f"unscoped tenant IDs would be hidden and frozen ({detail}). Assign "
                "them to a tenant first: `maverick tenant backfill <tenant_id>` "
                "(preview with `maverick tenant rls-preflight`). To opt into RLS "
                "knowingly without backfilling, set MAVERICK_PG_RLS=1 explicitly."
            )

    def _fill_stamped_tenants(self) -> None:
        """Fill the events' and episodes' tenant copy before a policy reads it.

        Runs when row-level security is turned on for a store migration 56
        did not fill. Each batch of ``_STAMP_FILL_BATCH`` ids is its own short
        transaction, so no lock is held for long; rows written meanwhile are
        stamped by the trigger. Only a login that can install the policies
        fills: any other is refused by ``_apply_rls`` as before.
        """
        try:
            with self._tx() as cur:
                cur.execute(
                    "SELECT r.rolsuper OR r.rolbypassrls OR pg_get_userbyid(c.relowner) = r.rolname "
                    "FROM pg_roles r, pg_class c WHERE r.rolname = current_user "
                    "AND c.oid = 'goals'::regclass")
                row = cur.fetchone()
        except Exception:  # unreadable catalog: the policy step reports the problem
            return
        if not (row and row[0]):
            return
        for table in _RLS_STAMPED_TABLES:
            with self._tx() as cur:
                cur.execute(f"SELECT COALESCE(max(id), 0) FROM {table}")
                top = int(cur.fetchone()[0])
            for low in range(0, top, _STAMP_FILL_BATCH):
                self._fill_stamped_batch(table, low, low + _STAMP_FILL_BATCH)
            with self._tx() as cur:
                cur.execute(f"CREATE INDEX IF NOT EXISTS idx_pg_{table}_tenant ON {table}(tenant_id)")

    def _fill_stamped_batch(self, table: str, low: int, high: int) -> None:
        """Fill one batch. Lifting FORCE queues an exclusive lock that other
        queries wait behind, so the batch waits at most 200 ms for it and is
        retried a few times before the start stops with a plain message."""
        for attempt in range(_STAMP_FILL_ATTEMPTS):
            try:
                with self._tx() as cur:
                    cur.execute("SET LOCAL lock_timeout = '200ms'")
                    cur.execute("SELECT relname FROM pg_class WHERE relforcerowsecurity "
                                "AND oid IN ('goals'::regclass, %s::regclass)", (table,))
                    forced = [row[0] for row in cur.fetchall()]
                    for name in forced:  # the owner must see every row; restored before commit
                        cur.execute(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY")
                    cur.execute(f"UPDATE {table} c SET tenant_id = g.tenant_id FROM goals g "
                                "WHERE g.id = c.goal_id AND c.id > %s AND c.id <= %s "
                                "AND c.tenant_id IS DISTINCT FROM g.tenant_id", (low, high))
                    for name in forced:
                        cur.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
                return
            except Exception as exc:
                if getattr(exc, "sqlstate", None) != "55P03":
                    raise
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(
            f"Turning on row-level security stopped while copying each {table} row's "
            "workspace, because goals was busy with other work. Nothing is lost: start "
            "Second Shift again when it is quieter, and it carries on where it stopped."
        )

    def _apply_rls(self) -> None:
        """Enable Postgres Row-Level Security on the tenant-scoped tables.

        Policy: a row is visible/writable only when its ``tenant_id`` equals the
        transaction-local ``maverick.tenant`` GUC set by ``_tx``. Unset, empty,
        or no-active-tenant GUC values match no rows. Current exact policies
        need only a catalog read; bootstrap/repair retains serialized DDL.

        Only a table's **owner** may ALTER it. A non-owner connection may start
        only if the owner/migration has already installed and forced the exact
        fail-closed policy; otherwise RLS startup raises instead of silently
        running without database-enforced tenant isolation.
        """
        if not all(self._rls_policy_is_active(t) for t in _RLS_STAMPED_TABLES):
            self._fill_stamped_tenants()
        for table in (*_RLS_TABLES, *_RLS_CHILD_TABLES):
            if self._rls_policy_is_active(table):
                continue
            try:
                with self._tx() as cur:
                    cur.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_ADVISORY_LOCK,))
                    # Another replica may have installed the policy while this
                    # connection waited. Inspect again on the writer's cursor.
                    if self._rls_policy_is_active(table, cursor=cur):
                        continue
                    cur.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
                    cur.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
                    cur.execute(f"DROP POLICY IF EXISTS mvk_tenant_isolation ON {table}")
                    cur.execute(self._rls_policy_sql(table))
                    if not self._rls_policy_is_active(table, cursor=cur):
                        raise RuntimeError("The exact tenant policy could not be verified.")
            except Exception as e:  # non-owner / insufficient privilege
                if self._rls_policy_is_active(table):
                    log.info(
                        "RLS already active on %s; continuing after setup error: %s",
                        table, e,
                    )
                    continue
                if table in _RLS_TENANT_COLUMN and self._rls_policy_is_active(
                    table, setting="maverick.tenant",
                ):
                    # The policy an earlier version installed is still forced,
                    # so isolation holds; refusing to start would take a
                    # working deployment down over a role it cannot change.
                    log.warning(
                        "RLS on %s still uses the policy an earlier version installed, and "
                        "this database role cannot replace it (%s). Tenant isolation stays "
                        "enforced, but a workspace whose id contains characters outside "
                        "A-Z a-z 0-9 . _ - cannot use its webhooks and deadline alerts "
                        "until Second Shift is started once as the table owner.",
                        table, e,
                    )
                    continue
                raise RuntimeError(
                    f"MAVERICK_PG_RLS is enabled but fail-closed RLS could not "
                    f"be installed or verified on {table}: {e}"
                ) from e

    @staticmethod
    def _rls_policy_sql(table: str) -> str:
        return _rls_policy_statement(table)

    def _rls_policy_is_active(self, table: str, *, cursor=None, setting: str | None = None) -> bool:
        """Verify FORCE and the complete stock policy before skipping DDL.

        Extra restrictive policies can narrow access. Another permissive policy
        can OR around isolation, so it is never evidence of a safe fast path.
        ``setting`` checks for the policy keyed on that session setting instead
        of the table's current one (the earlier workspace-table policy).
        """
        sql = (
            "SELECT c.relrowsecurity,c.relforcerowsecurity,p.polname,p.polcmd,"
            "p.polpermissive,p.polroles,pg_get_expr(p.polqual,p.polrelid),"
            "pg_get_expr(p.polwithcheck,p.polrelid) FROM pg_class c "
            "LEFT JOIN pg_policy p ON p.polrelid=c.oid WHERE c.oid=%s::regclass"
        )
        try:
            if cursor is not None:
                cursor.execute(sql, (table,))
                return self._rls_policy_rows_are_active(table, cursor.fetchall(), setting=setting)
            with self._tx() as cur:
                cur.execute(sql, (table,))
                rows = cur.fetchall()
        except Exception:
            return False
        return self._rls_policy_rows_are_active(table, rows, setting=setting)

    @staticmethod
    def _rls_policy_rows_are_active(table, rows, *, setting: str | None = None) -> bool:
        if not rows or not all(row[0] and row[1] for row in rows):
            return False
        policies = [row for row in rows if row[2] == "mvk_tenant_isolation"]
        if len(policies) != 1 or any(row[4] for row in rows if row[2] != "mvk_tenant_isolation"):
            return False
        policy = policies[0]
        if policy[3] != "*" or policy[4] is not True or list(policy[5] or ()) != [0]:
            return False
        tenant = "nullif(current_setting('maverick.tenant'::text,true),''::text)"
        if table in _RLS_CHILD_TABLES:
            parent, key = _RLS_CHILD_TABLES[table]
            expected = (f"exists(select1from{parent}pwhere((p.id={table}.{key})and"
                        f"(p.tenant_id={tenant})))")
            check = expected
            if table == "turns":
                check = (f"({expected})and((goal_idisnull)or(exists(select1fromgoalsgwhere("
                         f"(g.id=turns.goal_id)and(g.tenant_id={tenant})))))")
            expected = f"({expected})"
            check = f"({check})"
        else:
            column = _RLS_TENANT_COLUMN.get(table, "tenant_id")
            setting = setting or _rls_setting(table)
            expected = check = f"({column}=nullif(current_setting('{setting}'::text,true),''::text))"
        return ["".join(str(expr).lower().split()) for expr in policy[6:8]] == [expected, check]

    @staticmethod
    def _migration_version(cur) -> int | None:
        cur.execute("SELECT to_regclass('schema_migrations')")
        if not cur.fetchone()[0]:
            return None
        cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
        current = int((cur.fetchone() or [0])[0])
        if current > _PG_SCHEMA_VERSION:
            raise RuntimeError("The Postgres database schema is newer than this Second Shift installation.")
        return current

    def _migrate(self) -> None:
        """Apply pending migrations atomically, recording each in
        ``schema_migrations`` so a statement runs at most once.

        A current native migration record requires only a read. Bootstrap and
        upgrades take a transaction-scoped advisory lock so that concurrent
        replica startup serializes -- the second waiter re-reads the version
        after the first commits and applies nothing, rather than racing the
        non-concurrency-safe DDL."""
        with self._tx() as cur:
            if self._migration_version(cur) == _PG_SCHEMA_VERSION:
                return
        try:
            self._apply_pending_migrations()
        except Exception as exc:
            if getattr(exc, "sqlstate", None) != "42501":  # insufficient_privilege
                raise
            raise DatabaseUpgradeNeedsOwner(_PG_SCHEMA_VERSION) from None

    def _apply_pending_migrations(self) -> None:
        with self._tx() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_ADVISORY_LOCK,))
            # Re-read after waiting; an earlier replica may have upgraded it.
            if self._migration_version(cur) == _PG_SCHEMA_VERSION:
                return
            cur.execute(_MIGRATIONS_TABLE)
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
            current = int((cur.fetchone() or [0])[0])
            for version, statements in pending_migrations(current):
                for stmt in statements:
                    cur.execute(stmt)
                cur.execute(
                    "INSERT INTO schema_migrations(version, applied_at) "
                    "VALUES(%s, %s) ON CONFLICT (version) DO NOTHING",
                    (version, time.time()),
                )

    # ----- goal methods -----

    def create_goal(
        self,
        title: str,
        description: str = "",
        parent_id: int | None = None,
        *,
        owner: str = "",
        execution_principal: str = "",
        domain: str = "",
        project_id: int | None = None,
        connection_references: list | None = None,
    ) -> int:
        # `domain` and `project_id` mirror the SQLite backend's create_goal
        # signature. Both columns already exist on Postgres (migrations above)
        # and were settable after creation via set_goal_domain/set_goal_project,
        # but a caller that passes them AT creation (checkpoint sub-goal
        # spawning, the finance CLI) got a TypeError on this backend instead of
        # a created goal.
        if execution_principal is None:
            execution_principal = ""
        if not isinstance(execution_principal, str):
            raise ValueError("invalid execution principal")
        if execution_principal:
            from ..agent_control_plane import valid_principal

            if not valid_principal(execution_principal):
                raise ValueError("invalid execution principal")
        if connection_references:
            raise ValueError("connection references are not supported")
        selection = ""
        now = time.time()
        tenant = _active_tenant()
        with self._tx() as cur:
            for table, ref_id in (("goals", parent_id), ("projects", project_id)):
                if ref_id is not None:
                    ref_scope, ref_params = _mutation_tenant_scope()
                    cur.execute(
                        f"SELECT id FROM {table} WHERE id=%s AND " + ref_scope + " FOR SHARE",
                        (int(ref_id), *ref_params),
                    )
                    if cur.fetchone() is None:
                        raise ValueError(f"unknown {table} reference for the active tenant")
            cur.execute(
                "INSERT INTO goals(parent_id, title, description, status, "
                "created_at, updated_at, owner, execution_principal, domain, "
                "project_id, tenant_id, connection_selection) "
                "VALUES(%s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    parent_id,
                    _seal(title, "goals.title"),
                    _seal(description, "goals.description"),
                    now,
                    now,
                    owner,
                    execution_principal,
                    domain or "",
                    project_id,
                    tenant,
                    _seal(selection, "goals.connection_selection"),
                ),
            )
            row = cur.fetchone()
        return int(row[0])

    def get_goal(self, goal_id: int) -> PGGoal | None:
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id, tenant_id IS NULL "
            "FROM goals WHERE id=%s"
        )
        p: list = [goal_id]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        if row is None:
            return None
        return _dec_goal_row(row)

    def set_goal_status(self, goal_id: int, status: str, *, result: str | None = None) -> None:
        # Match SQLite's monotonically advancing optimistic review version.
        # GREATEST is evaluated against the row under the UPDATE lock, not a
        # stale client-side SELECT, including on a stalled/backwards clock.
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = (
            # COALESCE so a status-only update (result=None) doesn't wipe
            # an existing result -- matches the SQLite backend.
            "UPDATE goals SET completed_at=CASE WHEN %s <> 'done' THEN NULL "
            "WHEN status='done' THEN completed_at "
            "ELSE GREATEST(updated_at + 0.000001, %s) END, "
            "status=%s, result=COALESCE(%s, result), "
            "updated_at=GREATEST(updated_at + 0.000001, %s) WHERE id=%s "
            # A finished task stays finished: a late cancel changes nothing.
            "AND NOT (status='done' AND %s='cancelled')"
        )
        params: list = [status, now, status, _seal(result, "goals.result"), now, goal_id, status]
        if frag:
            sql += " AND " + frag
            params += fparams
        legacy_refused = False
        binding_scope = (execution_binding_lock(self, goal_id)
                         if status in {"active", "running"}
                         else nullcontext(False))
        with binding_scope as binding_locked, self._tx() as cur:
            if status in {"active", "running"}:
                scoped, scoped_params = _mutation_tenant_scope("g.tenant_id")
                current_sql = (
                    "SELECT g.status,g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                    "JOIN goal_origins o ON o.goal_id=g.id "
                    "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                    "AND a.tenant_id=COALESCE(g.tenant_id,'') "
                    "WHERE g.id=%s AND o.kind IN ('event','event_v2')"
                )
                if scoped:
                    current_sql += " AND " + scoped
                current_sql += " FOR UPDATE OF g,o"
                cur.execute(current_sql, (int(goal_id), *scoped_params))
                prior = cur.fetchone()
                if prior is None and binding_locked:
                    cur.execute("SELECT g.status FROM goals g WHERE g.id=%s" +
                                (" AND " + scoped if scoped else "") +
                                " FOR UPDATE OF g", (int(goal_id), *scoped_params))
                    current = cur.fetchone()
                    if current is not None and current[0] not in {"active", "running"}:
                        raise EventRegistryUnavailable("Event origin disappeared during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not binding_locked):
                    raise EventRegistryUnavailable("Event binding changed during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not compatible_event_goal(prior[2], prior[3], prior[1], prior[4])):
                    legacy_refused = True
                    if prior[0] == "pending":
                        cur.execute(
                            "UPDATE goals SET status='blocked', completed_at=NULL, "
                            "updated_at=GREATEST(updated_at + 0.000001, %s), "
                            "result=%s WHERE id=%s AND status='pending'"
                            + (" AND " + frag if frag else ""),
                            (now, _seal("Earlier event request held for review", "goals.result"),
                             int(goal_id), *fparams),
                        )
                        cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
            if not legacy_refused:
                cur.execute(sql, tuple(params))
            # Approval is bound to one terminal payload.  Invalidate it in the
            # same transaction on every rerun/non-terminal transition or result
            # mutation, after tenant-scoped UPDATE proves this goal is ours.
            if not legacy_refused and cur.rowcount == 1 and (status != "done" or result is not None):
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
        if legacy_refused:
            raise LegacyEventGoalHeld("Earlier event request held for review")

    def claim_goal_for_run(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Atomically claim a pending goal at the remote execution boundary.

        ``expected_owner`` rides in the same UPDATE as the pending-to-active
        compare-and-swap. Tenant mutation scope is exact: compatibility reads
        of legacy ``NULL`` rows do not grant authority to claim them.
        """
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = (
            "UPDATE goals SET status='active', updated_at=GREATEST(updated_at + 0.000001, %s) "
            "WHERE id=%s AND status='pending'"
        )
        params: list = [now, int(goal_id)]
        if expected_owner is not None:
            sql += " AND owner=%s"
            params.append(str(expected_owner))
        sql += " AND " + frag
        params += fparams
        with execution_binding_lock(self, goal_id) as binding_locked, self._tx() as cur:
            scoped, scoped_params = _mutation_tenant_scope("g.tenant_id")
            owner_sql = " AND g.owner=%s" if expected_owner is not None else ""
            cur.execute(
                "SELECT g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                "JOIN goal_origins o ON o.goal_id=g.id "
                "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                "AND a.tenant_id=COALESCE(g.tenant_id,'') "
                "WHERE g.id=%s AND g.status='pending' "
                "AND o.kind IN ('event','event_v2') "
                "AND " + scoped + owner_sql + " FOR UPDATE OF g,o",
                (int(goal_id), *scoped_params,
                 *((str(expected_owner),) if expected_owner is not None else ())),
            )
            legacy = cur.fetchone()
            if legacy is None and binding_locked:
                cur.execute(
                    "SELECT 1 FROM goals g WHERE g.id=%s AND g.status='pending' "
                    "AND " + scoped + owner_sql + " FOR UPDATE OF g",
                    (int(goal_id), *scoped_params,
                     *((str(expected_owner),) if expected_owner is not None else ())),
                )
                if cur.fetchone() is not None:
                    raise EventRegistryUnavailable("Event origin disappeared during execution claim")
            if legacy is not None and not binding_locked:
                raise EventRegistryUnavailable("Event binding changed during execution claim")
            if legacy is not None and not compatible_event_goal(
                    legacy[1], legacy[2], legacy[0], legacy[3]):
                cur.execute(
                    "UPDATE goals SET status='blocked', completed_at=NULL, "
                    "updated_at=GREATEST(updated_at + 0.000001, %s), result=%s "
                    "WHERE id=%s AND status='pending' AND " + frag,
                    (time.time(), _seal("Earlier event request held for review", "goals.result"),
                     int(goal_id), *fparams),
                )
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
                return False
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    def touch_goal(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Refresh a live goal's ``heartbeat_at`` (the orphan-reclaim liveness
        signal; ``updated_at`` stays the reviewed version) with no other side effect — the external-agent heartbeat
        primitive, mirroring the SQLite semantics: only in-flight rows
        qualify, and the owner predicate rides in the same statement."""
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = ("UPDATE goals SET heartbeat_at=GREATEST(heartbeat_at, %s) "
               "WHERE id=%s AND status IN ('active', 'pending')")
        params: list = [now, int(goal_id)]
        if expected_owner is not None:
            sql += " AND owner=%s"
            params.append(str(expected_owner))
        if frag:
            sql += " AND " + frag
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    # --- Backend parity (SQLite v13 -> v20 catch-up): methods on existing
    #     tables that the SQLite WorldModel exposes but the PG backend lacked.
    #     New-table methods (projects/share-links/sign-offs/artifacts/origin)
    #     follow in their own migrations. ----------------------------------

    def list_approvals(self, limit: int = 500) -> list:
        """All approvals, newest first (the Operating Record's decision feed)."""
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold, "
            "tenant_id IS NULL "
            "FROM approvals"
        )
        p: list = list(params) if frag else []
        if frag:
            sql += " WHERE " + frag
        sql += " ORDER BY requested_at DESC, id DESC LIMIT %s"
        p.append(max(1, int(limit)))
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        return [_dec_approval_row(r) for r in rows]

    def release_processed_message(self, channel: str, external_id: str) -> None:
        """Undo a ``mark_message_processed`` claim so a failed run can retry."""
        with self._tx() as cur:
            cur.execute(
                "DELETE FROM processed_messages "
                "WHERE COALESCE(tenant_id, '') = COALESCE(%s, '') "
                "AND channel = %s AND external_id = %s",
                (_active_tenant(), channel, external_id),
            )

    # ---- Projects (migration v15) -------------------------------------------

    _PROJECT_COLS = "id, name, description, owner, domain, status, created_at, tenant_id IS NULL"

    # -- backend-portable raw reads (mirror of WorldModel.query) -------------

    def query(self, sql: str, params: tuple | list = (), *, system: bool = False) -> list:
        """Run a read-only statement written in SQLite paramstyle (``?``).

        The statement is rewritten for psycopg (``%s``, ``%%``), executed inside
        :meth:`_tx` (so it takes the connection lock, sets the tenant GUC and
        rolls back on error instead of poisoning the shared connection), and
        every row comes back as a tuple that also supports ``row["column"]``.

        This statement carries no tenant predicate, so it is refused while
        tenancy is on (a bound tenant, strict isolation or row-level security)
        unless ``system=True`` marks a deliberate deployment-wide read. Tenant
        data goes through :meth:`tenant_query`.
        """
        if not system and self._tenancy_on():
            from ..tenant_sql import TenantScopeRequired
            raise TenantScopeRequired(
                "This read has no tenant boundary. Use tenant_query, or mark a "
                "deployment-wide read with system=True.")
        return self._raw_query(sql, params)

    def _tenancy_on(self) -> bool:
        return bool(self._rls) or _strict_tenant_isolation() or _active_tenant() is not None

    def _raw_query(self, sql: str, params: tuple | list = ()) -> list:
        params = tuple(params)
        with self._tx() as cur:
            if params:
                cur.execute(_to_pg_paramstyle(sql), params)
            else:
                cur.execute(sql)
            columns = {d.name: i for i, d in enumerate(cur.description or ())}
            rows = cur.fetchall()
        return [_PgRow.wrap(r, columns) for r in rows]

    def ping(self) -> bool:
        """Cheap liveness probe for ``/healthz`` -- confirms Postgres answers a
        trivial read so the deep health check probes the SAME store the app uses."""
        with self._tx() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True

    # ---- Artifacts (migration v16) ------------------------------------------

    # ---- Share links (migration v17) ----------------------------------------

    # ---- Sign-offs (migration v17) ------------------------------------------

    # ---- Goal origins (migration v17) ---------------------------------------

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
    ) -> list[PGGoal]:
        """List goals, optionally filtered by status + paginated (mirrors SQLite).

        ``domain``/``project_id`` were missing here (unlike SQLite's
        ``list_goals``), so the dashboard's project-detail page and
        domain-scoped inbox both 500 on this backend --
        ``list_goals(project_id=...)`` / ``list_goals(domain=...)`` raised
        ``TypeError`` for a keyword this method didn't accept.
        ``before_id`` is an exclusive immutable ID bound, combined with all
        current tenant/owner filters without reading its anchor. Descending
        order provides continuation; ascending order only applies the bound.
        ``strict_tenant`` excludes legacy unbound rows for named workspaces,
        regardless of the deployment's compatibility setting.
        """
        if before_id is not None and not 0 < int(before_id) <= 2**63 - 1:
            raise ValueError("before_id must be a positive signed 64-bit goal ID")
        direction = "DESC" if str(order).lower() == "desc" else "ASC"
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id, tenant_id IS NULL "
            "FROM goals"
        )
        params: list = []
        conds: list[str] = []
        if status:
            conds.append("status = %s")
            params.append(status)
        if owner is not None:
            conds.append("owner = %s")
            params.append(str(owner))
        if domain is not None:
            conds.append("domain = %s")
            params.append(domain)
        if project_id is not None:
            conds.append("project_id = %s")
            params.append(int(project_id))
        if before_id is not None:
            conds.append("id < %s")
            params.append(int(before_id))
        if strict_tenant:
            tenant = _active_tenant()
            frag, fparams = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        else:
            frag, fparams = _tenant_scope()
        if frag:
            conds.append(frag)
            params += fparams
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += f" ORDER BY id {direction}"
        if limit is not None:
            sql += " LIMIT %s OFFSET %s"
            params += [max(1, int(limit)), max(0, int(offset))]
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    # ----- episodes -----

    def start_episode(self, goal_id: int) -> int:
        # Child rows (episodes/events/turns/...) carry no tenant_id; they inherit
        # tenancy through their goal/conversation FK, and reads enforce it via a
        # JOIN. The writes must too: gate the insert on the parent goal being in
        # the active tenant so a write against another tenant's goal_id can't
        # land. Legacy rows require an unbound caller.
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO episodes(goal_id, started_at) SELECT %s, %s "
                    "WHERE EXISTS (SELECT 1 FROM goals WHERE id=%s AND "
                    + frag + ") RETURNING id",
                    (goal_id, time.time(), goal_id, *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO episodes(goal_id, started_at) VALUES(%s, %s) "
                    "RETURNING id",
                    (goal_id, time.time()),
                )
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0])

    def _episode_tenant_cond(self) -> tuple[str, list]:
        """SQL fragment + params restricting an episode UPDATE (keyed by
        episode_id) to episodes whose parent goal is owned by the active scope."""
        frag, fparams = _mutation_tenant_scope()
        if not frag:
            return "", []
        return (" AND goal_id IN (SELECT id FROM goals WHERE " + frag + ")", fparams)

    def end_episode(
        self,
        episode_id: int,
        summary: str,
        outcome: str,
        *,
        cost_dollars: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        cond, cparams = self._episode_tenant_cond()
        with self._tx() as cur:
            cur.execute(
                "UPDATE episodes SET ended_at=%s, summary=%s, outcome=%s, "
                "cost_dollars=%s, input_tokens=%s, output_tokens=%s, "
                "tool_calls=%s, cache_read_tokens=%s, cache_write_tokens=%s "
                "WHERE id=%s" + cond,
                (time.time(), _seal(summary, "episodes.summary"), _seal(outcome, "episodes.outcome"),
                 cost_dollars, input_tokens, output_tokens, tool_calls,
                 cache_read_tokens, cache_write_tokens, episode_id, *cparams),
            )

    def list_episodes(
        self,
        limit: int = 50,
        goal_id: int | None = None,
        owner: str | None = None,
    ) -> list:
        """Recent run-cost episodes, newest first.

        ``owner`` scopes to one principal's runs through the owning goal;
        ``None`` retains the tenant-wide admin/auth-off view. Tenant and owner
        predicates are cumulative, so an owner filter can never widen the
        active tenant boundary.
        """
        from ..world_records import EpisodeSpend
        cols = (
            "e.id, e.goal_id, e.started_at, e.ended_at, e.outcome, "
            "COALESCE(e.cost_dollars, 0), COALESCE(e.input_tokens, 0), "
            "COALESCE(e.output_tokens, 0), COALESCE(e.tool_calls, 0), "
            "COALESCE(e.cache_read_tokens, 0), COALESCE(e.cache_write_tokens, 0), "
            + _legacy_of("goals", "e.goal_id")
        )
        frag, fparams = _tenant_scope("g.tenant_id")
        conds: list[str] = []
        params: list = []
        table = "episodes e"
        if frag or owner is not None:
            table += " JOIN goals g ON g.id = e.goal_id"
        if goal_id is not None:
            conds.append("e.goal_id = %s")
            params.append(goal_id)
        if owner is not None:
            conds.append("g.owner = %s")
            params.append(owner)
        if frag:
            conds.append(frag)
            params += fparams
        sql = f"SELECT {cols} FROM {table}"
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY e.started_at DESC LIMIT %s"
        params.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        # outcome (index 4) is sealed at rest; the rest are numeric/timestamps.
        return [EpisodeSpend(r[0], r[1], r[2], r[3],
                             _unseal(r[4], "episodes.outcome", legacy_row=r[11]),
                             r[5], r[6], r[7], r[8], r[9], r[10]) for r in rows]

    def total_spend(self, owner: str | None = None, *,
                    since: float | None = None) -> dict[str, float]:
        """Aggregate spend. ``owner`` scopes to one principal's runs (join to
        the owning goal), matching the SQLite backend's signature; ``None``
        is the deployment-wide admin / auth-off view; ``since`` keeps only runs
        that started at or after that time, as on SQLite. Owner-scoped callers
        (``/api/v1/spend``, external-agent spend records) rely on ``owner``.
        """
        frag, params = _tenant_scope("g.tenant_id")
        table = "episodes e"
        if frag or owner is not None:
            table += " JOIN goals g ON g.id = e.goal_id"
        sql = (
            "SELECT COALESCE(SUM(e.cost_dollars), 0), COALESCE(SUM(e.input_tokens), 0), "
            "COALESCE(SUM(e.output_tokens), 0), COUNT(*) "
            f"FROM {table} WHERE e.ended_at IS NOT NULL"
        )
        if frag:
            sql += " AND " + frag
        if owner is not None:
            sql += " AND g.owner = %s"
            params = (*params, owner)
        if since is not None:
            sql += " AND e.started_at >= %s"
            params = (*params, float(since))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        return {
            "dollars": row[0],
            "input_tokens": row[1],
            "output_tokens": row[2],
            "runs": row[3],
        }

    def agent_spend_groups(self, *, since: float, until: float) -> list:
        """Aggregate completed outside-agent episodes without sharing legacy rows."""
        from ..world_records import AgentSpendGroup

        scope, params = _mutation_tenant_scope("g.tenant_id")
        with self._tx() as cur:
            cur.execute(
                "SELECT g.owner, g.domain, to_char(to_timestamp(floor(e.ended_at)) AT TIME ZONE 'UTC', 'YYYY-MM') AS month, "
                "COALESCE(SUM(e.cost_dollars), 0), COUNT(*) "
                "FROM episodes e JOIN goals g ON e.goal_id = g.id "
                "WHERE e.ended_at >= %s AND e.ended_at < %s AND substr(g.owner, 1, 6) = 'agent:' "
                f"AND length(g.owner) > 6 AND {scope} GROUP BY g.owner, g.domain, month",
                (since, until, *params),
            )
            return [AgentSpendGroup(*row) for row in cur.fetchall()]

    # ----- events -----

    def append_event(self, goal_id: int, agent: str, kind: str, content: str) -> int:
        # Gate on the parent goal being in the active tenant (see start_episode).
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO goal_events(goal_id, agent, kind, content, ts) "
                    "SELECT %s, %s, %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ") RETURNING id",
                    (goal_id, agent, kind, _seal(content, "goal_events.content"), time.time(),
                     goal_id, *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO goal_events(goal_id, agent, kind, content, ts) "
                    "VALUES(%s, %s, %s, %s, %s) RETURNING id",
                    (goal_id, agent, kind, _seal(content, "goal_events.content"), time.time()),
                )
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0])

    # ----- facts (global key/value memory) -----

    # ----- questions (ask_user / human-in-the-loop) -----

    # ----- approvals (high-risk action consent queue) -----

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

        ``provenance`` is trusted caller-supplied metadata for operator UIs; it
        is not inferred from ``detail`` (which may carry untrusted text).
        ``approvals_required`` is the N-of-M quorum; ``requested_by`` the
        requester (so a multi-party approval can bar self-approval).
        ``undoable`` mirrors SQLite: only a requester that waits out the undo
        window before acting sets it."""
        from ..logging_config import current_goal_id
        from ..world_model import APPROVAL_UNDO_OPEN

        context_goal = current_goal_id()
        frag, fparams = _mutation_tenant_scope()
        goal_sql = "SELECT id, domain FROM goals WHERE id=%s"
        if frag:
            goal_sql += " AND " + frag
        goal_sql += " FOR SHARE"
        with self._tx() as cur:
            cur.execute(goal_sql, tuple([context_goal, *fparams]))
            goal = cur.fetchone()
            if context_goal is not None and goal is None:
                raise ValueError("approval goal is unavailable for the active tenant")
            cur.execute(
                "INSERT INTO approvals(action, risk, scope, detail, provenance, status, "
                "requested_at, tenant_id, approvals_required, requested_by, goal_id, department, "
                "undo_hold) VALUES(%s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING id",
                (_seal(action, "approvals.action"), risk, _seal(scope, "approvals.scope"), _seal(detail, "approvals.detail"), provenance,
                 time.time(), _active_tenant(), max(1, int(approvals_required)),
                 (requested_by or None), goal[0] if goal else None, goal[1] if goal else "",
                 APPROVAL_UNDO_OPEN if undoable else None),
            )
            row = cur.fetchone()
        from ..world_model import _notify_approval_created

        _notify_approval_created(self, int(row[0]), provenance)
        self._emit_approval_event("approval.created", int(row[0]), {"risk": risk, "action": action})
        return int(row[0])

    def _emit_approval_event(self, event: str, approval_id: int, payload: dict) -> None:
        """Webhook subscribers hear about approvals, as on SQLite; call it only
        after the transaction has committed. Never raises."""
        from ..world_model import WorldModel

        WorldModel._emit_approval_event(self, event, approval_id, payload)

    def get_approval(self, approval_id: int, *, strict_tenant: bool = False):
        if strict_tenant:
            tenant = _active_tenant()
            frag, params = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        else:
            frag, params = _tenant_scope()
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold, "
            "tenant_id IS NULL "
            "FROM approvals WHERE id = %s"
        )
        p: list = [approval_id]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        return _dec_approval_row(row) if row else None

    def pending_unattached_approval_ids(self, owner: str, *, limit: int) -> list[int]:
        tenant = _active_tenant()
        scope, params = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        with self._tx() as cur:
            cur.execute(
                "SELECT id FROM approvals WHERE status='pending' AND goal_id IS NULL "
                f"AND requested_by=%s AND {scope} ORDER BY id DESC LIMIT %s",
                tuple([owner, *params, max(1, int(limit))]),
            )
            rows = cur.fetchall()
        return [int(row[0]) for row in rows]

    def pending_approvals(self) -> list:
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold, "
            "tenant_id IS NULL "
            "FROM approvals WHERE status = 'pending'"
        )
        if frag:
            sql += " AND " + frag
        sql += " ORDER BY id"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_approval_row(r) for r in rows]

    def approval_audit_event_id(
        self,
        approval_id: int,
        status: str,
        decided_by: str,
    ) -> str:
        from ..world_model import _approval_audit_event_id

        with self._tx() as cur:
            undo_round = self._approval_undo_round(cur, approval_id)
        return _approval_audit_event_id(
            _active_tenant(),
            approval_id,
            status,
            (decided_by or "").strip(),
            undo_round,
        )

    def _approval_undo_round(self, cur, approval_id: int) -> int:
        """How many times this approval was undone (mirrors SQLite)."""
        from ..world_model import APPROVAL_UNDO_STATUS

        outbox_scope, outbox_params = _approval_outbox_scope()
        cur.execute(
            "SELECT COUNT(*) FROM approval_audit_outbox "
            f"WHERE approval_id = %s AND status = %s AND {outbox_scope}",
            tuple([int(approval_id), APPROVAL_UNDO_STATUS, *outbox_params]),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def get_approval_audit_event(self, event_id: str):
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                f"WHERE event_id = %s AND {scope}",
                tuple([str(event_id), *params]),
            )
            row = cur.fetchone()
        return _dec_approval_audit_row(row) if row else None

    def pending_approval_audit_events(
        self,
        *,
        approval_id: int | None = None,
        limit: int = 100,
    ) -> list:
        scope, params = _approval_outbox_scope()
        sql = (
            "SELECT event_id, approval_id, status, decided_by, final_status, "
            "created_at, delivered_at FROM approval_audit_outbox "
            f"WHERE delivered_at IS NULL AND {scope}"
        )
        values: list = list(params)
        if approval_id is not None:
            sql += " AND approval_id = %s"
            values.append(int(approval_id))
        sql += " ORDER BY created_at, event_id LIMIT %s"
        values.append(max(1, min(int(limit), 1000)))
        with self._tx() as cur:
            cur.execute(sql, tuple(values))
            rows = cur.fetchall()
        return [_dec_approval_audit_row(row) for row in rows]

    def approval_has_pending_finalization(self, approval_id: int) -> bool:
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = %s AND final_status IS NOT NULL "
                f"AND delivered_at IS NULL AND {scope} LIMIT 1",
                tuple([int(approval_id), *params]),
            )
            row = cur.fetchone()
        return row is not None

    def _require_locked_approval_review(self, cur, approval_id: int, status: str,
                                        approver: str, event_id: str, review: dict, effect_guard=None) -> None:
        """Read reviewed card, quorum and content owner under the held row lock."""
        from ..approval_vote_review import require_locked_vote_review
        from ..world_model import _single_approver

        approval_scope, approval_params = _mutation_tenant_scope()
        outbox_scope, outbox_params = _approval_outbox_scope()
        sql = ("SELECT id, action, risk, scope, detail, provenance, status, requested_at, decided_at, claimed_by, claimed_at, decided_by, approvals_required, requested_by, goal_id, department, undo_hold FROM approvals WHERE id = %s")
        values = [int(approval_id)]
        if approval_scope:
            sql += " AND " + approval_scope
            values += approval_params
        cur.execute(sql, tuple(values))
        locked = cur.fetchone()
        exact = _dec_approval_row(locked) if locked is not None else None
        cur.execute("SELECT approver, decision FROM approval_signoffs WHERE approval_id = %s ORDER BY decided_at", (int(approval_id),))
        approvers = _single_approver(exact, [row[0] for row in cur.fetchall() if row[1] == "approved"]) if exact is not None else []
        cur.execute(f"SELECT COUNT(*) FROM approval_audit_outbox WHERE approval_id = %s AND delivered_at IS NULL AND {outbox_scope}", tuple([int(approval_id), *outbox_params]))
        audit_pending = int(cur.fetchone()[0])
        content_owner = (exact.requested_by or "") if exact is not None else None
        if exact is not None and exact.goal_id:
            owner_sql = "SELECT owner,domain FROM goals WHERE id = %s"
            owner_values = [exact.goal_id]
            if approval_scope:
                owner_sql += " AND " + approval_scope
                owner_values += approval_params
            cur.execute(owner_sql + " FOR SHARE", tuple(owner_values))
            source = cur.fetchone()
            content_owner = (source[0] or "") if source is not None else None
            source_guard = getattr(effect_guard, "approval_source", None)
            if source_guard is not None:
                source_guard(exact.goal_id, content_owner, source[1] if source is not None else None)
        require_locked_vote_review(exact, review, status=status, actor=approver,
                                   event_id=event_id, approvers=approvers, audit_pending=audit_pending,
                                   content_owner=content_owner)

    def decide_approval_audited(
        self,
        approval_id: int,
        status: str,
        *,
        decided_by: str,
        reviewed_card: dict | None = None,
        effect_guard=None,
    ):
        """Atomically accept a vote and queue its signed-audit delivery."""
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        approver = (decided_by or "").strip()
        if not approver:
            return None

        from ..world_model import _approval_audit_event_id
        from ..world_records import ApprovalAuditEvent

        tenant = _active_tenant()
        approval_scope, approval_params = _mutation_tenant_scope()
        outbox_scope, outbox_params = _approval_outbox_scope()
        approval_sql = (
            "SELECT status, approvals_required, requested_by "
            "FROM approvals WHERE id = %s"
        )
        approval_values: list = [int(approval_id)]
        if approval_scope:
            approval_sql += " AND " + approval_scope
            approval_values += approval_params
        approval_sql += " FOR UPDATE"

        with self._tx() as cur:
            # Row lock serializes duplicate and competing votes across replicas.
            cur.execute(approval_sql, tuple(approval_values))
            approval = cur.fetchone()
            if effect_guard:
                effect_guard()
            undo_round = self._approval_undo_round(cur, approval_id)
            event_id = _approval_audit_event_id(
                tenant, approval_id, status, approver, undo_round,
            )

            if reviewed_card is not None:
                self._require_locked_approval_review(cur, approval_id, status, approver, event_id, reviewed_card, effect_guard)

            cur.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                f"WHERE event_id = %s AND {outbox_scope}",
                tuple([event_id, *outbox_params]),
            )
            prior = cur.fetchone()
            if prior is not None:
                prior_event = _dec_approval_audit_row(prior)
                if not prior_event.matches(approval_id, status, approver):
                    raise RuntimeError(
                        "approval audit outbox event identity is corrupt"
                    )
                return prior_event
            if approval is None or approval[0] != "pending":
                return None

            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = %s AND final_status IS NOT NULL "
                f"AND delivered_at IS NULL AND {outbox_scope} LIMIT 1",
                tuple([int(approval_id), *outbox_params]),
            )
            if cur.fetchone() is not None:
                return None

            required = max(1, int(approval[1] or 1))
            requested_by = approval[2]
            if (
                required > 1
                and status == "approved"
                and requested_by
                and person_key(approver) == person_key(requested_by)
            ):
                from ..safety.dual_control import allow_self_approval

                if not allow_self_approval():
                    return None

            now = time.time()
            final_status = None
            if required <= 1:
                final_status = status
            else:
                # Backfill pending pre-v30 signoffs into the new outbox before
                # a later vote can reach quorum. This keeps upgraded databases
                # from signing only the final vote in an N-of-M decision.
                cur.execute(
                    "SELECT approver, decision, decided_at "
                    "FROM approval_signoffs WHERE approval_id = %s "
                    "ORDER BY decided_at, approver",
                    (int(approval_id),),
                )
                for legacy in cur.fetchall():
                    legacy_event_id = _approval_audit_event_id(
                        tenant, approval_id, legacy[1], legacy[0], undo_round,
                    )
                    cur.execute(
                        "INSERT INTO approval_audit_outbox("
                        "event_id, approval_id, status, decided_by, final_status, "
                        "created_at, delivered_at, tenant_id) "
                        "VALUES(%s, %s, %s, %s, NULL, %s, NULL, %s) "
                        "ON CONFLICT (event_id) DO NOTHING",
                        (
                            legacy_event_id,
                            int(approval_id),
                            legacy[1],
                            legacy[0],
                            float(legacy[2]),
                            tenant,
                        ),
                    )
                cur.execute(
                    "SELECT event_id, approval_id, status, decided_by, final_status, "
                    "created_at, delivered_at FROM approval_audit_outbox "
                    f"WHERE event_id = %s AND {outbox_scope}",
                    tuple([event_id, *outbox_params]),
                )
                prior = cur.fetchone()
                if prior is not None:
                    prior_event = _dec_approval_audit_row(prior)
                    if not prior_event.matches(approval_id, status, approver):
                        raise RuntimeError(
                            "approval audit outbox event identity is corrupt"
                        )
                    return prior_event

                cur.execute(
                    "SELECT decision FROM approval_signoffs "
                    "WHERE approval_id = %s AND approver = %s",
                    (int(approval_id), approver),
                )
                existing_signoff = cur.fetchone()
                if (
                    existing_signoff is not None
                    and existing_signoff[0] != status
                ):
                    return None
                cur.execute(
                    "INSERT INTO approval_signoffs(approval_id, approver, decision, "
                    "decided_at) VALUES(%s, %s, %s, %s) "
                    "ON CONFLICT (approval_id, approver) DO NOTHING",
                    (int(approval_id), approver, status, now),
                )
                if status == "denied":
                    final_status = "denied"
                else:
                    cur.execute(
                        "SELECT approver FROM approval_signoffs "
                        "WHERE approval_id = %s AND decision = 'approved'",
                        (int(approval_id),),
                    )
                    if distinct_people(row[0] for row in cur.fetchall()) >= required:
                        final_status = "approved"

            cur.execute(
                "INSERT INTO approval_audit_outbox("
                "event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at, tenant_id) "
                "VALUES(%s, %s, %s, %s, %s, %s, NULL, %s)",
                (
                    event_id,
                    int(approval_id),
                    status,
                    approver,
                    final_status,
                    now,
                    tenant,
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
            if effect_guard:
                effect_guard()
            return result

    def mark_approval_audit_delivered(
        self,
        event_id: str,
        *,
        delivered_at: float | None = None,
        effect_guard=None,
    ) -> bool:
        """Acknowledge signed delivery and apply any now-safe final outcome."""
        outbox_scope, outbox_params = _approval_outbox_scope()
        approval_scope, approval_params = _mutation_tenant_scope()
        finalized: tuple[str, str] | None = None
        with self._tx() as cur:
            cur.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                f"WHERE event_id = %s AND {outbox_scope} FOR UPDATE",
                tuple([str(event_id), *outbox_params]),
            )
            event = cur.fetchone()
            if effect_guard is not None:
                effect_guard()
            if event is None:
                return False
            source_guard = getattr(effect_guard, "approval_source", None)
            if source_guard is not None:
                goal_scope, goal_params = _mutation_tenant_scope("g.tenant_id")
                cur.execute("SELECT g.id,g.owner,g.domain FROM approvals a JOIN goals g ON g.id=a.goal_id WHERE a.id=%s" + (" AND " + goal_scope if goal_scope else "") + " FOR SHARE OF g", tuple([event[1], *goal_params]))
                source = cur.fetchone()
                if source is None:
                    raise PermissionError("The original approval task is unavailable")
                source_guard(source[0], source[1] or "", source[2])
            # The decision takes effect at delivery, so the undo window starts
            # here and not at the vote (same rule as the SQLite backend).
            delivery_time = (
                float(event[6])
                if event[6] is not None
                else float(delivered_at) if delivered_at is not None else time.time()
            )
            if event[6] is None:
                cur.execute(
                    "UPDATE approval_audit_outbox SET delivered_at = %s "
                    f"WHERE event_id = %s AND delivered_at IS NULL AND {outbox_scope}",
                    tuple([delivery_time, str(event_id), *outbox_params]),
                )

            approval_id = int(event[1])
            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                f"WHERE approval_id = %s AND delivered_at IS NULL AND {outbox_scope} "
                "LIMIT 1",
                tuple([approval_id, *outbox_params]),
            )
            if cur.fetchone() is None:
                cur.execute(
                    "SELECT final_status, decided_by "
                    "FROM approval_audit_outbox "
                    f"WHERE approval_id = %s AND final_status IS NOT NULL "
                    f"AND {outbox_scope} "
                    "ORDER BY created_at DESC, event_id DESC LIMIT 1",
                    tuple([approval_id, *outbox_params]),
                )
                final = cur.fetchone()
                if final is not None:
                    sql = (
                        "UPDATE approvals SET status = %s, decided_at = %s, "
                        "decided_by = %s WHERE id = %s AND status = 'pending'"
                    )
                    values: list = [
                        final[0],
                        delivery_time,
                        final[1],
                        approval_id,
                    ]
                    if approval_scope:
                        sql += " AND " + approval_scope
                        values += approval_params
                    cur.execute(sql, tuple(values))
                    if cur.rowcount > 0:
                        finalized = (final[0], final[1])
            if effect_guard is not None:
                effect_guard()
        # Only after the guard passed and the transaction committed (as on SQLite).
        if finalized is not None:
            self._emit_approval_event("approval.decided", approval_id,
                                      {"status": finalized[0], "decided_by": finalized[1] or ""})
        return True

    def approval_state(self, approval_id: int) -> dict | None:
        """Quorum progress for an approval (tenant-scoped), or None if unknown.
        Mirrors the SQLite backend's shape."""
        appr = self.get_approval(approval_id)
        if appr is None:
            return None
        with self._tx() as cur:
            cur.execute(
                "SELECT approver, decision FROM approval_signoffs "
                "WHERE approval_id = %s ORDER BY decided_at, approver", (approval_id,),
            )
            rows = cur.fetchall()
        from ..world_model import _approval_state_view, _single_approver

        approvers = _single_approver(appr, [r[0] for r in rows if r[1] == "approved"])
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM approval_audit_outbox "
                f"WHERE approval_id = %s AND delivered_at IS NULL AND {scope}",
                tuple([approval_id, *params]),
            )
            audit_pending = int(cur.fetchone()[0])
        return _approval_state_view(appr, approvers, audit_pending)

    def pending_approval_signoffs(self, approval_ids: list[int]) -> dict[int, list[str]]:
        """Approved votes on the requested rows that are pending in this tenant."""
        if not approval_ids:
            return {}
        scope, params = _tenant_scope("a.tenant_id")
        with self._tx() as cur:
            cur.execute(
                "SELECT a.id, s.approver FROM approvals a LEFT JOIN approval_signoffs s "
                "ON s.approval_id = a.id AND s.decision = 'approved' "
                f"WHERE a.status = 'pending' AND a.id = ANY(%s) AND {scope} "
                "ORDER BY a.id, s.decided_at, s.approver", (approval_ids, *params),
            )
            rows = cur.fetchall()
        result: dict[int, list[str]] = {}
        for approval_id, approver in rows:
            votes = result.setdefault(approval_id, [])
            if approver is not None:
                votes.append(approver)
        return result

    # ----- conversations / turns (multi-turn channel memory) -----

    # ----- messages (goal-scoped log) -----

    # ----- attachments -----

    # ----- channel dedup (inbound-message idempotency) -----

    def mark_message_processed(
        self, channel: str, external_id: str, goal_id: int | None = None,
    ) -> bool:
        """Record an inbound message as processed; idempotent. Returns True on
        first-write (caller should run the goal), False on duplicate (caller
        returns 200 without re-running). Mirrors SQLite — protects against
        Twilio/iMessage webhook retries producing N goals + N spends."""
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO processed_messages(channel, external_id, goal_id, seen_at, tenant_id) "
                "VALUES(%s, %s, %s, %s, %s) "
                "ON CONFLICT ((COALESCE(tenant_id, '')), channel, external_id) DO NOTHING",
                (channel, external_id, goal_id, time.time(), _active_tenant()),
            )
            # rowcount is 1 on insert, 0 when the conflict skipped it.
            return cur.rowcount == 1

    # ----- cluster-wide killswitch (v22) -----
    # Untenanted single-row global emergency stop; on shared Postgres every
    # replica's killswitch.check() consults this so a halt stops the whole fleet.
    def arm_halt(self, reason: str = "", source: str = "manual",
                 armed_by: str = "") -> str:
        generation = secrets.token_urlsafe(24)
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO halt(scope, reason, source, armed_by, armed_at, generation) "
                "VALUES('', %s, %s, %s, %s, %s) "
                "ON CONFLICT(scope) DO UPDATE SET reason=EXCLUDED.reason, "
                "source=EXCLUDED.source, armed_by=EXCLUDED.armed_by, "
                "armed_at=EXCLUDED.armed_at, generation=EXCLUDED.generation",
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
        """Bind a durable local clear to the exact locked shared generation."""
        if not isinstance(expected_generation, str):
            raise TypeError("expected_generation must be a string")
        with self._tx() as cur:
            cur.execute(
                "SELECT generation FROM halt WHERE scope = '' FOR UPDATE"
            )
            row = cur.fetchone()
            if row is None or (row[0] or "") != expected_generation:
                return False
            if durable_clear is not None:
                durable_clear()
            cur.execute(
                "DELETE FROM halt WHERE scope = '' AND generation = %s",
                (expected_generation,),
            )
            deleted = cur.rowcount
        return bool(deleted and deleted > 0)

    def active_halt(self) -> dict | None:
        with self._tx() as cur:
            cur.execute(
                "SELECT reason, source, armed_by, armed_at, generation "
                "FROM halt WHERE scope = ''")
            row = cur.fetchone()
        if row is None:
            return None
        return {"reason": row[0] or "", "source": row[1] or "",
                "armed_by": row[2] or "", "armed_at": row[3],
                "generation": row[4] or ""}

    # ----- pruning -----

    @property
    def schema_version(self) -> int:
        """Schema version, for parity with SQLite WorldModel.schema_version
        (read as a property by health.py + audit events). Derived from the
        MIGRATIONS ladder (``_PG_SCHEMA_VERSION = MIGRATIONS[-1][0]``)."""
        return _PG_SCHEMA_VERSION

    # ----- close -----

    def close(self) -> None:
        try:
            if self._pool is not None:
                self._pool.close()
            elif self.conn is not None:
                self.conn.close()
        except Exception:  # pragma: no cover
            pass


def open_postgres_world(dsn: str | None = None) -> PostgresWorldModel:
    """Open a Postgres world model. Convenience wrapper that resolves DSN."""
    return PostgresWorldModel(dsn=dsn)


def is_postgres_configured() -> bool:
    """True if config / env requests the postgres backend."""
    if os.environ.get("MAVERICK_WORLD_BACKEND", "").strip().lower() == "postgres":
        return True
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("world_model") or {}
        return (cfg.get("backend") or "").strip().lower() == "postgres"
    except Exception:
        return False


__all__ = [
    "PostgresWorldModel",
    "PGGoal",
    "open_postgres_world",
    "is_postgres_configured",
    "SCHEMA",
]
