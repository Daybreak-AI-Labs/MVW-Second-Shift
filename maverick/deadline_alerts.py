"""Alerts when a privacy or governance record is due.

Nothing used to tell anyone that a data-subject request, an incident's
72-hour notification clock, an assessment renewal, a vendor contract renewal
or an approval was about to run out. This module evaluates every such record
in the workspace and sends plain-language alerts through the notification
backends already configured in ``[notifications]`` (ntfy, Pushover, Slack,
Discord today; e-mail or Teams when those backends exist, since delivery goes
through :func:`maverick.notifications.notify`).

Each record gets at most one alert per *state* (``due_soon_7d``,
``due_soon_2d``, ``due_today``, ``overdue`` ...) per deadline. The ledger
(``deadline_alerts`` table in the world database) records what was sent, so a
restart never re-sends and the record page can show its alert history. A
deadline that moves (an extension) is a new deadline and starts over.

Only a delivery that at least one channel accepted is recorded as sent. A
definite "not sent" (no backend configured, every backend refused) records
nothing in the ledger, so the alert stays due -- but it is retried after a
growing wait (5, 10, 20, 40, 60 minutes, then hourly), kept in its own small
store (``deadline-alert-retries.json``) rather than the ledger or the
delivery receipts, and retried at once when the notification setup changes.
A workspace with no working channel therefore neither floods the delivery
history nor blocks other notifications, and still alerts once it is repaired.
An uncertain outcome (a backend may have sent before failing) is recorded as
*unconfirmed* -- shown in the alert history, never replayed automatically.

Configuration (``~/.maverick/config.toml``)::

    [deadline_alerts]
    enabled = true          # default: on when the privacy register is on
    mode = "immediate"      # or "digest": one message per recipient per cycle
    poll_seconds = 900
    quiet_hours = "22:00-07:00"   # server local time; incidents still go through
    owner = "the privacy owner"   # who is alerted when a record has no assignee

    [deadline_alerts.lead_days]
    dsar = [7, 2]
    assessment = [30, 7]
    vendor = [30, 7]

    [deadline_alerts.lead_hours]
    incident = [24, 4]
    approval = [24, 4]

Routing: a record with an assignee is alerted "for" that person; otherwise
the workspace's privacy/governance owner named above. Per-person channels do
not exist in the notification layer yet, so both go to the workspace's
configured backends with the recipient named in the message; when a
per-recipient backend lands, :func:`deliver` is the single seam to route by
``recipient``.
"""
from __future__ import annotations

SQLITE_SCHEMA: list[str] = [
    "CREATE TABLE IF NOT EXISTS deadline_alerts ("
    " id TEXT PRIMARY KEY, workspace TEXT NOT NULL DEFAULT '',"
    " record_type TEXT NOT NULL, record_id TEXT NOT NULL, state TEXT NOT NULL,"
    " due_at REAL NOT NULL, recipient TEXT NOT NULL DEFAULT '',"
    " recipient_kind TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',"
    " message TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',"
    " sent_at REAL NOT NULL, backends INTEGER NOT NULL DEFAULT 0,"
    " mode TEXT NOT NULL DEFAULT 'immediate')",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_deadline_alerts_once"
    " ON deadline_alerts(workspace, record_type, record_id, state, due_at)",
    "CREATE INDEX IF NOT EXISTS idx_deadline_alerts_record"
    " ON deadline_alerts(record_type, record_id, sent_at DESC)",
]
POSTGRES_SCHEMA: list[str] = [s.replace(" REAL", " DOUBLE PRECISION") for s in SQLITE_SCHEMA]


__all__ = [
]
