"""Indexed PostgreSQL identity records preserve sign-in behavior at MVW size."""
from __future__ import annotations

import json


def test_names_import_once_and_remain_sealed(records_in_postgres, tmp_path, monkeypatch):
    import psycopg

    from maverick import crypto_at_rest, record_documents
    from maverick_dashboard import account_profiles

    monkeypatch.setenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    previous = {"schema": 1, "profiles": {"user:old": {"at": 10, "name": "Existing private name", "email": ""}}}
    record_documents.at(account_profiles._path()).write_text(json.dumps(previous))
    account_profiles.record_sign_in("user:new", {"name": "New private name"})
    assert set(account_profiles._read()) == {"user:new", "user:old"}
    with psycopg.connect(records_in_postgres) as db:
        bodies = db.execute("SELECT body FROM second_shift_keyed_records WHERE address='account-profiles.json'").fetchall()
    assert len(bodies) == 2
    assert all(crypto_at_rest.is_sealed_str(body) and "private name" not in body for (body,) in bodies)
    account_profiles.record_sign_in("user:old", {})
    assert set(account_profiles._read()) == {"user:new"}
    assert not (tmp_path / "account-profiles.json").exists()


def test_subject_links_and_revocations_keep_their_authority(records_in_postgres):
    from maverick import record_documents, teams_identity
    from maverick_dashboard import session_revocation, subject_directory

    subject_directory.record_login("first", ["employee@example.test"], at=100)
    assert subject_directory.subject_for("EMPLOYEE@example.test") == "first"
    subject_directory.record_login("second", ["employee@example.test"], at=101)
    assert subject_directory.subject_for("employee@example.test") == "second"
    session_revocation.revoke_principal("user:second", at=300)
    session_revocation.revoke_principal("user:second", at=200)
    assert session_revocation.is_revoked("user:second", 299)
    assert not session_revocation.is_revoked("user:second", 300)
    teams_identity.link("employee@example.test", "user:second")
    teams_identity.pin_upn("employee@example.test", "10000000-1111-1111-1111-111111111111")
    assert teams_identity.principal_for("10000000-1111-1111-1111-111111111111") == "user:second"
    assert teams_identity.principal_for("employee@example.test") is None
    assert len(teams_identity.links_for_principal("user:second")) == 1
    assert record_documents.at(subject_directory._path()).read_text() is None


def test_sign_in_uses_the_same_indexed_operations_at_mvw_size(records_in_postgres, monkeypatch):
    from maverick import record_documents, teams_identity
    from maverick_dashboard import account_profiles, session_revocation, subject_directory

    monkeypatch.setenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", "1")
    profile = account_profiles._encode({"name": "Employee", "email": "", "at": 1})
    original = record_documents._run
    observed = []
    active_measurement = False

    def track(cursor, statement, parameters):
        result = original(cursor, statement, parameters)
        if active_measurement:
            observed.append((statement, cursor.rowcount))
        return result

    monkeypatch.setattr(record_documents, "_run", track)

    def seed(begin, end):
        with account_profiles._keyed().transaction(account_profiles._migrate, write=True) as store:
            store.rows("people").seed((f"user:employee-{idx}", profile, "", 1.0) for idx in range(begin, end))
        with subject_directory._keyed().transaction(subject_directory._migrate, write=True) as store:
            store.rows("people").seed((subject_directory._subject_key(f"employee-{idx}"),
                                       json.dumps({"sub": f"employee-{idx}", "ts": 1}), "", 1.0)
                                      for idx in range(begin, end))
            store.rows("aliases").seed((
                subject_directory._key(alias), subject_directory._subject_key(f"employee-{idx}"), "", 1.0,
            ) for idx in range(begin, end) for alias in (f"employee-{idx}@example.test", f"employee-{idx}"))
        with session_revocation._keyed().transaction(session_revocation._migrate, write=True) as store:
            store.rows("people").seed((f"user:employee-{idx}", "1.0", "", 1.0) for idx in range(begin, end))
        with teams_identity._keyed().transaction(teams_identity._migrate, write=True) as store:
            store.rows("links").seed((f"employee-{idx}", json.dumps({"principal": f"user:employee-{idx}"}),
                                      f"user:employee-{idx}", 1.0) for idx in range(begin, end))

    def sign_in(name):
        nonlocal active_measurement
        observed.clear()
        active_measurement = True
        try:
            account_profiles.record_sign_in("user:employee-0", {"name": name})
            subject_directory.record_login("employee-0", ["employee-0@example.test", "employee-0"], at=20)
            assert subject_directory.subject_for("employee-0@example.test") == "employee-0"
            assert session_revocation.revocation_epoch("user:employee-0") == 1
            assert teams_identity.principal_for("employee-0") == "user:employee-0"
        finally:
            active_measurement = False
        return tuple(observed)

    seed(0, 25)
    small = sign_in("New name")
    seed(25, 25000)
    large = sign_in("Another name")
    assert 10 < len(small) <= 32 and all(rows <= 1 for _, rows in small)
    assert large == small
