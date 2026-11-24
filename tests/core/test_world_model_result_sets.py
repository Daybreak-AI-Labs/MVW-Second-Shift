"""Result sets resolve the at-rest policy and the key once per query.

Decoding row by row checked the policy (the compliance profile configuration)
and loaded the key for every sealed field: listing 500 approvals took 250-450
ms, and a page reading 500 runs or facts paid the same again. Each batch must
read exactly as its rows decoded one at a time.
"""
from __future__ import annotations

import sqlite3

import pytest

from maverick import world_model


def _rows(path, sql):
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql).fetchall()


@pytest.fixture
def sealed_world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    path = tmp_path / "w.db"
    wm = world_model.WorldModel(path)
    return wm, path


def test_with_encryption_off_values_pass_through_untouched(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    path = tmp_path / "w.db"
    wm = world_model.WorldModel(path)
    wm.create_approval("email.send", scope="crm", detail="hello")
    rows = _rows(path, "SELECT * FROM approvals")
    assert rows[0]["action"] == "email.send"
    assert world_model._approvals_from_rows(rows) == [world_model._approval_from_row(rows[0])]
    assert world_model._approvals_from_rows([]) == []
    assert world_model._goals_from_rows([]) == []
    assert world_model._episode_spends_from_rows([]) == []
