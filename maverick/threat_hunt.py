"""Agent-attack hunter -- sweep the audit trail for attacks by or against agents.

Every safety-relevant thing an agent does or has done to it lands in the audit
log: the shield blocking a prompt injection, the egress lock refusing a cloud
call (an exfiltration attempt), a sub-agent denied for trying to exceed its
capability grant, a governance policy firing, the kill switch. This module sweeps
that trail and aggregates those signals into a risk-rated **threat report** --
"search everywhere agents leave a trace, and surface the attacks."

The audit log is already secret-redacted before write, and only event *metadata*
(kind / agent / goal / provider / tool / reason) is summarised here -- never
payload content. Fail-soft like the audit reader it builds on.

Surfaced as ``maverick hunt`` and (next) the threat-hunter agent that investigates
each finding.
"""
from __future__ import annotations

# Audit event kinds that signal a security event, with a description + severity.
# Each is an attack *by* an agent (exfiltration, escalation) or *against* one
# (injection), or a control firing in response.
_INDICATORS: dict[str, tuple[str, str]] = {
    "shield_block": (
        "Shield blocked unsafe content (prompt injection / jailbreak / policy)",
        "high"),
    "egress_blocked": (
        "Exfiltration attempt: an egress to a non-local provider was blocked",
        "high"),
    "capability_denied": (
        "Privilege escalation: an agent tried to exceed its capability grant",
        "high"),
    "governance_denied": (
        "Governance policy denied an action", "medium"),
    "halt": (
        "Kill switch engaged (HALT)", "medium"),
    "secret_redacted": (
        "Secret detected and redacted before write", "low"),
    "consent_result": (
        "Destructive action denied or timed out at the consent gate", "medium"),
}


__all__ = [
]
