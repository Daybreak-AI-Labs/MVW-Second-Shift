"""Approval queue: world-model persistence + consent dashboard mode."""
from __future__ import annotations

from maverick.world_model import SCHEMA_VERSION, WorldModel


def test_schema_has_approvals_table(tmp_path):
    wm = WorldModel(path=tmp_path / "world.db")
    assert wm.schema_version == SCHEMA_VERSION
    # The approvals table exists and is queryable.
    assert wm.pending_approvals() == []


def test_create_approval_preserves_trusted_provenance(tmp_path):
    wm = WorldModel(path=tmp_path / "world.db")
    aid = wm.create_approval(
        "shell", risk="high", detail="operator review", provenance="governance"
    )

    row = wm.get_approval(aid)
    assert row is not None
    assert row.provenance == "governance"
    assert wm.pending_approvals()[0].provenance == "governance"
