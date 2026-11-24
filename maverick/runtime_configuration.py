"""Startup configuration receipts for observed long-lived processes.

These acknowledge the configuration read during process initialization, not
provider health or successful execution. Heartbeats never replace the startup
snapshot with newly saved settings. No value or credential is published.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
_CAPTURE = None
_CAPTURE_LOCK = threading.RLock()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def snapshot(configuration, environment=None):
    environment = dict(os.environ) if environment is None else environment
    values = {}
    def visit(value, path):
        if path:
            values[json.dumps(path)] = _digest([True, value])
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, [*path, str(key)])
    visit(configuration, [])
    env = {name: _digest(value) for name, value in environment.items()}
    return {"values": values, "environment": env, "revision": _digest([configuration, env])}


def remember(configuration, *, valid=True):
    """Capture once at the first global config read; no disk IO or recursive reads."""
    global _CAPTURE
    if _CAPTURE is not None:
        return
    with _CAPTURE_LOCK:
        if _CAPTURE is None:
            _CAPTURE = {**snapshot(configuration), "captured_at": time.time(), "valid": valid}
