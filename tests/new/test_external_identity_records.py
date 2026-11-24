"""The replay ledger with Postgres: a request that was claimed once is refused
the second time, and an unreadable ledger refuses every claim."""
from __future__ import annotations

import pytest

from maverick import external_identity as xi
from tests.new.conftest import saved_records


def test_with_postgres_a_nonce_claimed_once_is_refused_the_second_time(tmp_path, records_in_postgres):
    assert xi.claim_once("vega", "nonce-1", expires_at=2000.0, now=1000.0) is None
    assert xi.claim_once("vega", "nonce-1", expires_at=2000.0, now=1001.0) == "replay"
    assert xi.claim_once("vega", "nonce-2", expires_at=2000.0, now=1002.0) is None
    assert xi.claim_once("other", "nonce-1", expires_at=2000.0, now=1003.0) is None
    assert not (tmp_path / "external-replay.json").exists()
    assert "external-replay.json" in saved_records(records_in_postgres)
    # Once the claim has expired the key may be used again.
    assert xi.claim_once("vega", "nonce-1", expires_at=4000.0, now=3000.0) is None


def test_with_postgres_an_unreadable_replay_ledger_is_refused(records_in_postgres):
    import psycopg

    xi.claim_once("vega", "nonce-1", expires_at=2000.0, now=1000.0)
    with psycopg.connect(records_in_postgres) as connection:
        connection.execute("UPDATE second_shift_records SET body = %s WHERE key = %s",
                           ("{not json", "external-replay.json"))
    with pytest.raises(xi.ReplayStoreError):
        xi.claim_once("vega", "nonce-2", expires_at=2000.0, now=1001.0)
