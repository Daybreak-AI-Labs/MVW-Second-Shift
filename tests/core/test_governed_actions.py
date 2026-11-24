"""Governed Actions: typed ops + simulate-before-commit + tamper-evident lineage."""
from __future__ import annotations

import json

import pytest

from maverick import governed_actions as ga_mod


def test_record_tool_lineage_is_fail_open(tmp_path):
    # A bad goal_id type must not raise (lineage never breaks a run).
    ga_mod.record_tool_lineage("not-an-int", "shell", {}, store_dir=tmp_path)  # no exception


def test_lineage_never_persists_raw_text_when_redaction_is_unavailable(
    monkeypatch, tmp_path,
):
    def _unavailable(_value):
        raise RuntimeError("detector unavailable")

    monkeypatch.setattr("maverick.safety.secret_detector.redact", _unavailable)
    assert ga_mod.record_tool_lineage(
        5,
        "connector.write.commit",
        {"private": "never-store-this"},
        result="never-store-this",
        force=True,
        strict=True,
        store_dir=tmp_path,
    )
    raw = (tmp_path / "5.ndjson").read_text(encoding="utf-8")
    assert "never-store-this" not in raw
    assert "redaction unavailable" in raw


def test_strict_receipt_failure_propagates(tmp_path):
    with pytest.raises(ValueError):
        ga_mod.record_tool_lineage(
            "not-an-int", "connector.write.prepare", {}, force=True,
            strict=True, store_dir=tmp_path,
        )


def test_strict_receipt_refuses_to_extend_a_tampered_chain(tmp_path):
    assert ga_mod.record_tool_lineage(
        18, "connector.write.prepare", {"value": "original"}, force=True,
        strict=True, store_dir=tmp_path,
    )
    ledger = tmp_path / "18.ndjson"
    link = json.loads(ledger.read_text(encoding="utf-8"))
    link["params_json"] = '{"value":"tampered"}'
    ledger.write_text(json.dumps(link) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="lineage is not trustworthy"):
        ga_mod.record_tool_lineage(
            18, "connector.write.commit", {"value": "original"}, force=True,
            strict=True, store_dir=tmp_path,
        )

    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1
