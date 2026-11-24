"""Audit log for Second Shift.

Append-only NDJSON sink at ``~/.maverick/audit/YYYY-MM-DD.ndjson``.
Daily rotation. Each line is a versioned JSON event.

Event types (see ``events.py``):
  - goal_start / goal_end       — goal lifecycle
  - episode_start / episode_end — best-of-N attempt lifecycle
  - tool_call / tool_result     — every tool invocation
  - shield_block                — Shield denied an input/output/tool call
  - consent_prompt / consent_result — destructive-action gates
  - secret_redacted             — secret detector hit
  - erase                       — GDPR Art.17 erasure
  - halt                        — killswitch fired

This module is intentionally minimal. Ordinary audit failures are logged and
remain best-effort. An explicit AuditRefused is different: when a deployment's
required signing or custody policy cannot be satisfied, callers must propagate
the refusal rather than continue an action with weaker evidence than promised.
"""
from __future__ import annotations

from importlib import import_module
from typing import Any

# Keep package import side-effect free. In particular, offline signature and
# checkpoint verification must not import writer.py, whose live sink resolves
# deployment config and tenant storage. Public names retain their historical
# ``maverick.audit`` locations and are cached after first use.
_EXPORT_MODULE = {
    "AuditRefused": ".errors",
    "EventKind": ".events",
    "audit_event": ".writer",
    "record": ".writer",
    "record_global": ".writer",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULE.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value

__all__ = [
    "EventKind",
    "AuditRefused",
    "audit_event",
    "record",
    "record_global",
]
