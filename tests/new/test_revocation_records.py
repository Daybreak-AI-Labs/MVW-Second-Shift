"""The revocation list with Postgres: a revoked principal is kept in the
database, every reader sees a change at once, and an unreadable row denies."""
from __future__ import annotations

import pytest

from maverick import revocation
from tests.new.conftest import saved_records


@pytest.fixture(autouse=True)
def _fresh():
    revocation.reset_shared()
    yield
    revocation.reset_shared()


def test_with_postgres_a_revocation_is_kept_there_and_seen_by_every_reader(tmp_path, records_in_postgres):
    reader = revocation.RevocationRegistry()
    writer = revocation.RevocationRegistry()
    assert reader.is_revoked("user:amy") is False
    writer.revoke("user:amy", reason="left the company")
    assert reader.is_revoked("user:amy") is True
    assert writer.unrevoke("user:amy") is True
    assert reader.is_revoked("user:amy") is False
    writer.revoke("user:bo", reason="leaked key")
    assert set(revocation.shared().revoked()) == {"user:bo"}
    assert not (tmp_path / "capability_revocations.json").exists()
    assert "capability_revocations.json" in saved_records(records_in_postgres)


def test_with_postgres_an_unreadable_revocation_record_denies(records_in_postgres):
    import psycopg

    revocation.shared().revoke("user:amy", reason="left the company")
    with psycopg.connect(records_in_postgres) as connection:
        connection.execute("UPDATE second_shift_records SET body = %s WHERE key = %s",
                           ("{not json", "capability_revocations.json"))
    with pytest.raises(revocation.RevocationStoreError):
        revocation.RevocationRegistry().revoked()
    assert revocation.is_revoked("user:anyone") is True
