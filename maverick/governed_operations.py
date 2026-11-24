"""Durable operation bindings shared by bounded application services.

The owning domain persists the operation before calling a provider. Existing
GovernedActions still supplies typed simulation, approval gating and lineage.
An ``executing`` record after restart is ambiguous, never permission to retry.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def digest(value: Any, *, default: Any = None) -> str:
    return hashlib.sha256(json.dumps(
        value, default=default, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()
