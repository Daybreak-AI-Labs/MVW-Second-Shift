"""Audit event schema. Versioned, additive-only.

To add a new event kind:
  1. Add it to ``EventKind`` here.
  2. Bump ``SCHEMA_VERSION`` if the payload shape changes for an
     EXISTING kind (new kinds are additive — no bump needed).
  3. Document the payload shape in this file's module docstring.

Payload shapes (kind -> required fields, all events also carry
``ts``, ``goal_id``, ``agent``, ``kind``):

  goal_start:        title:str, description:str|None
  goal_end:          status:str (succeeded|failed|cancelled), result:str|None
  episode_start:     attempt:int, model:str
  episode_end:       outcome:str, cost_dollars:float, in_tok:int, out_tok:int
  tool_call:         name:str, call_id:str, call_commitment:str,
                     call_commitment_algorithm:str, input_summary:str (truncated);
                     records an attempted governed dispatch, not completion
  tool_result:       name:str, call_id:str, call_commitment:str,
                     call_commitment_algorithm:str, status:str, output_summary:str;
                     status=ok is the execution-completion evidence
  shield_block:      stage:str (input|tool|output), reason:str, score:float|None
  ifc_flow:          tool:str, labels:list[str], explicit:list[str], mode:str,
                     outcome:str (recorded|approved|denied|blocked); labelled data
                     reaching an external sink (maverick.ifc); never arguments
  capability_denied: tool:str, principal:str, channel:str|None, user_id:str|None
  egress_blocked:    provider:str (enterprise-mode egress lock denial)
  consent_prompt:    action:str, risk:str (low|medium|high|critical)
  consent_result:    decision:str (approve|deny|timeout)
  secret_redacted:   tool_name:str, pattern:str, count:int
  erase:             channel:str, erasure_id:str (random token, never subject-derived)
  halt:              source:str (file|signal|manual), detail:str|None
  content_update:    content:str, version:int, year:int, publisher:str
                     (signed publisher content metadata; no tax table bodies)
  federation_delegate: peer_node:str (absent when the caller was unauthenticated),
                     correlation_id:str, direction:str (sent|received),
                     accepted:bool, reason:str ("" when accepted) — one half of a
                     cross-swarm delegation; the two halves share the
                     correlation_id
  agent_trust_denied: peer:str, direction:str (inbound|outbound), rule:str,
                     reason:str, correlation_id:str — an external agent was
                     refused by the Agent Trust Plane.
  agent_trust_changed: action:str (added|replaced|limits_changed|blocked|
                     unblocked|removed), trusted_agent:str, actor:str — an
                     app-managed Agent Trust entry changed; written before the
                     change is saved, so a failed save leaves a record of the
                     attempt with no change.
  privacy_record_changed: event_id:str, occurred_at:float, actor:str, tenant:str,
                     record_type:str, action:str, record_id:str, revision:int,
                     status:str, record_sha256:str (opaque control metadata and
                     a content commitment only; never DPA text, subject ids,
                     RoPA content, or export bodies)
  security_suite_control_changed: actor:str, previous:dict, requested:dict
                     (deployment-global enablement of GRC/platform-hunt/env-hunt
                     and response execution; no connector credentials)
  security_record_changed: event_id:str, occurred_at:float, actor:str, tenant:str,
                     record_type:str, action:str, record_id:str, revision:int,
                     status:str, record_sha256:str (opaque lifecycle metadata and
                     a content commitment only; never evidence or case content)
  platform_hunt_detection: finding_id:str, rule_id:str, severity:str, score:int,
                     mitre_techniques:list[str], evidence_ids:list[str],
                     finding_sha256:str
  platform_hunt_custody_initialized: event_id:str, version:int, purpose:str,
                     occurred_at:float (insert-once witness that the hunter's
                     signed audit custody was successfully initialized)
  threat_hunt_record_changed: event_id:str, record_type:str, record_id:str,
                     revision:int, action:str, actor:str, record_sha256:str,
                     status:str, occurred_at:float
  env_hunt_record_changed: same bounded derived-record mutation shape as
                     threat_hunt_record_changed
  env_hunt_ingestion: connector:str, query_sha256:str, events_received:int,
                     events_accepted:int, events_discarded:int, raw_persisted:bool
  env_hunt_detection: same bounded shape as platform_hunt_detection
  env_hunt_enrichment: investigation_id:str, source:str,
                     indicator_sha256:str, fields_sha256:str
  env_hunt_response_proposed: proposal_id:str, proposal_sha256:str, action:str,
                     target_sha256:str, evidence_ids:list[str]
  env_hunt_response_authorized: proposal_id:str, proposal_sha256:str,
                     approval_id:str, approver:str, executor:str
  env_hunt_response_executed: proposal_id:str, proposal_sha256:str,
      approval_id:str, approver:str, executor:str, outcome:str
  env_hunt_response_ambiguous: proposal_id:str, proposal_sha256:str,
      approval_id:str, executor:str, error_kind:str
  env_hunt_response_execution_claimed: proposal_id:str, proposal_sha256:str,
      approval_id:str, executor:str, actor:str
  unified_audit_projection: projection_event_id:str, projection_type:str,
                     tenant_sha256:str, source_id:str, suite_id:str,
                     source_schema_version:int, source_authority_revision:int,
                     source_authority_sha256:str, source_sequence:int;
                     ``source_record`` rows carry only stable record digests and
                     a closed action code, while ``source_page_receipt`` rows
                     carry the page/head/watermark/completeness commitments plus
                     verifier, trust-root, key, anchor and retention commitments,
                     raw_source_payload_persisted:false (digest-only custody
                     projection of a domain-owned event; never raw source
                     payloads, actors, or resource ids)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 2

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def is_valid_day(day: Any) -> bool:
    """True iff ``day`` is a real ``YYYY-MM-DD`` calendar date.

    An audit ``day`` becomes a filesystem path component
    (``<audit_dir>/<day>.ndjson``), so anything that isn't this exact shape
    -- ``..``, a path separator, an absolute path, a NUL -- could escape the
    audit dir. The anchored shape check is the path-safety gate; on top of it
    we require a genuine calendar date, so a typo'd ``--day`` (``2026-13-99``,
    ``2026-02-30``) is a friendly error instead of a misleading "no entries /
    OK" on a day-file that could never exist. Every code path that
    builds a day-file path from an untrusted ``day`` must gate on this first.
    (Mirrors the dashboard's own ``safe_audit_day`` HTTP-boundary guard.)
    """
    if not (isinstance(day, str) and _DAY_RE.match(day)):
        return False
    import datetime
    try:
        datetime.date.fromisoformat(day)
    except ValueError:
        return False
    return True


class EventKind:
    """Stringly-typed event kinds. Use these constants, not bare strings."""
    CAPABILITY_DENIED = "capability_denied"
    EGRESS_BLOCKED  = "egress_blocked"
    CONSENT_RESULT  = "consent_result"
    HALT            = "halt"
    # A user's dashboard access changed: privilege role (global or per-tenant),
    # department (suite) grant, or one atomic SCIM group-authority mutation.
    # One row per change makes who-granted-whom-what-when provable instead of a
    # silent JSON edit. SCIM batch rows carry a stable scim_group_event_id,
    # old/new names, and complete member-set deltas or bounded commitments.
    ACCESS_GRANT_CHANGED = "access_grant_changed"
    FEDERATION_DELEGATE = "federation_delegate"
    # Agent Trust Plane: an external agent was refused an inbound action or an
    # outbound dial because it is absent from the [agent_trust] registry, its
    # direction forbade the interaction, or it exceeded its tool/risk ceiling.
    # payload: peer:str, direction:str (inbound|outbound), rule:str, reason:str,
    # correlation_id:str ("" when none).
    AGENT_TRUST_DENIED = "agent_trust_denied"
    # An app-managed entry in the Agent Trust registry changed, written before
    # the change is saved. payload: action (added|replaced|limits_changed|
    # blocked|unblocked|removed), trusted_agent:str, actor:str.
    AGENT_TRUST_CHANGED = "agent_trust_changed"
    # Agent Control Plane: an operator verb (suspend / resume / contain /
    # release / attenuate / halt / clear-halt) applied to a governed principal
    # from the console or `maverick control-plane`. payload: verb:str,
    # principal:str ("*" for a fleet verb), actor:str, ok:bool (what was
    # CONFIRMED to land, not what was asked), detail:str; attenuate adds
    # ceiling:dict (the narrowed deny_tools / max_risk / caps). Dashboard HALT
    # rows additionally carry operation:str, scope:str (local|cluster),
    # result:str (succeeded|failed|partial), and a bounded reason:str.
    CONTROL_PLANE_ACTION = "control_plane_action"
    BREAK_GLASS_TOKEN_USED = "break_glass_token_used"  # pragma: allowlist secret - an event name
    EXTERNAL_AGENT_ENROLLED = "external_agent_enrolled"
    EXTERNAL_CREDENTIAL_MINTED = "external_credential_minted"
    EXTERNAL_RUN_INGESTED = "external_run_ingested"
    EXTERNAL_ACTION_SCREENED = "external_action_screened"
    # Containment lifecycle: CONTAINED fires when repeated denials inside the
    # window trip the auto-containment (payload: external_agent, denials,
    # window_hours, last_rule); RELEASED and BUDGET_RESET are the admin
    # actions that lift it / zero the meter (payload carries who did it).
    EXTERNAL_AGENT_CONTAINED = "external_agent_contained"
    EXTERNAL_AGENT_RELEASED = "external_agent_released"
    EXTERNAL_BUDGET_RESET = "external_budget_reset"
    # A LIVE external run opened (goal_id carries the row; the matching
    # close is EXTERNAL_RUN_INGESTED with live=True).
    EXTERNAL_RUN_STARTED = "external_run_started"
    # The enforcement tier above screening: Second Shift PERFORMED an outbound
    # action on an external agent's behalf through a governed connector.
    # Payload: external_agent, connector, op, outcome (executed|failed),
    # request_sha256, approved (True when it went through a parked
    # approval), goal_id when the run bound one. Never the request body or
    # the response text — those stay out of the audit row by design.
    # (Previews and parks audit as ACTION_SCREENED — no effect occurred.)
    EXTERNAL_ACTION_EXECUTED = "external_action_executed"
    # Learning governance: one row per dream cycle (what the learning system
    # wrote/retired/quarantined) so `maverick audit verify` covers learned
    # state the same way it covers tool calls.
    LEARNING_UPDATE = "learning_update"
    # Human-oversight decision on a parked approval (approve/deny). Anchors the
    # who-decided-what in the signed chain so the integrity of the decision does
    # not rest on the mutable world-model `approvals` row alone.
    # payload: approval_event_id:str (stable transactional-outbox identity),
    # approval_id:int, status:str (approved|denied), decided_by:str,
    # occurred_at:float (when the vote and outbox row committed).
    APPROVAL_DECISION = "approval_decision"
    # Cross-suite audit custody. Domain stores remain authoritative; this event
    # is the signed, append-once digest projection that makes their evidence
    # visible to the tenant audit/SIEM/WORM plane. ``projection_event_id`` is a
    # stable delivery identity. Stable record rows are separate from mandatory
    # signed page receipts, including receipts for empty terminal snapshots.
    # All source identities/content are closed codes or digests.
    UNIFIED_AUDIT_PROJECTION = "unified_audit_projection"
    # A privacy record mutation. The originating record retains a durable
    # audit-outbox receipt until this event is accepted by the signed chain.
    PRIVACY_RECORD_CHANGED = "privacy_record_changed"
    SECURITY_RECORD_CHANGED = "security_record_changed"
    PLATFORM_HUNT_CUSTODY_INITIALIZED = "platform_hunt_custody_initialized"
    THREAT_HUNT_RECORD_CHANGED = "threat_hunt_record_changed"
    ENV_HUNT_RECORD_CHANGED = "env_hunt_record_changed"


@dataclass
class AuditEvent:
    """One audit log row. ``payload`` is event-specific (see module doc)."""
    ts: float
    kind: str
    agent: str = "system"
    goal_id: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        # Strip reserved keys from payload before the spread: a payload key
        # named v/ts/kind/agent/goal_id would otherwise clobber the canonical
        # structural field, losing it and corrupting the signed-hash input.
        _reserved = {"v", "ts", "kind", "agent", "goal_id"}
        safe_payload = {k: val for k, val in self.payload.items() if k not in _reserved}
        return {
            "v": self.schema_version,
            "ts": self.ts,
            "kind": self.kind,
            "agent": self.agent,
            "goal_id": self.goal_id,
            **safe_payload,
        }
