"""Compliance-regime profiles are not part of this product: no profile is ever active.

Callers ask whether an active profile requires a protection floor; the answer
here is always no, so each protection follows its own setting.
"""
from __future__ import annotations

FLOOR_PII_REDACTION = "pii_redaction"
FLOOR_ENCRYPTION_AT_REST = "encryption_at_rest"
FLOOR_EGRESS_LOCK = "egress_lock"
FLOOR_AUDIT_LOG = "audit_log"


def resolve_profiles(config: object = None, *, source_errors: object = None) -> tuple[str, ...]:
    return ()


def required_floors(keys) -> frozenset[str]:
    return frozenset()


def requires_floor(floor: str) -> bool:
    return False
