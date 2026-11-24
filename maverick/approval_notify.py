"""Announcing a new approval in a chat channel is not part of this product yet.

New approvals wait in the web app's queue; nothing is posted elsewhere.
"""
from __future__ import annotations


def approval_created(approval_id: int, *, provenance: str = "", world=None) -> None:
    return None
