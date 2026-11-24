"""Execution backends.

Local (subprocess), Docker (throwaway containers), SSH (remote host
via system ssh binary). All implement ``.exec(cmd) -> ExecResult``
so the agent loop is backend-agnostic.

The agent never instantiates a backend directly -- always go through
``build_sandbox()`` so the [sandbox] config section is the single
source of truth.
"""
from __future__ import annotations

__all__ = [
]
