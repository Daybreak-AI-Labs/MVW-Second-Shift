"""The sign-in and permission records kept with the other records in Postgres."""
from __future__ import annotations

import json

import pytest

from tests.new.conftest import saved_records


def _put(path, value):
    from maverick import record_documents

    record_documents.at(path).write_text(value if isinstance(value, str) else json.dumps(value))


def test_the_role_list_is_read_from_postgres(records_in_postgres, tmp_path):
    from maverick_dashboard import rbac

    _put(rbac.store_path(), {"alice": "operator"})
    _put(rbac.custom_roles_path(), {"night-desk": {"permissions": ["view", "audit"], "description": "x"}})
    _put(rbac.tenant_store_path(), {"t1": {"bob": "night-desk"}})
    assert rbac.list_users() == {"alice": "operator"}
    assert rbac.is_known_role("night-desk")
    assert rbac.get_tenant_role("t1", "bob") == "night-desk"
    assert rbac.tenant_role_scope_initialized() is True
    assert list(tmp_path.glob("dashboard-*")) == []
    keys = saved_records(records_in_postgres)
    assert {"dashboard-users.json", "dashboard-custom-roles.json", "dashboard-tenant-roles.json"} <= set(keys)
    assert "dashboard-users.json.present" in keys  # the roster is remembered there too


def test_a_missing_role_list_that_was_recorded_is_refused_in_postgres(records_in_postgres):
    from maverick_dashboard import rbac

    _put(rbac.store_path(), {"alice": "viewer"})
    assert rbac.list_users() == {"alice": "viewer"}
    # remove the roster record entirely, as a lost file would be
    import psycopg

    with psycopg.connect(records_in_postgres) as connection:
        connection.execute("DELETE FROM second_shift_records WHERE key = 'dashboard-users.json'")
    with pytest.raises(rbac.RosterMissingError):
        rbac.list_users()


def test_a_corrupt_role_list_in_postgres_is_refused(records_in_postgres):
    from maverick_dashboard import rbac

    _put(rbac.store_path(), "{not json")
    with pytest.raises(rbac.RbacStoreError):
        rbac.list_users()
    _put(rbac.store_path(), {"alice": "no-such-role"})
    with pytest.raises(rbac.RbacStoreError):
        rbac.list_users()


def test_page_visibility_is_read_from_postgres(records_in_postgres, tmp_path):
    from maverick_dashboard import ui_visibility

    page = next(iter(ui_visibility._PAGES_BY_PATH))
    _put(ui_visibility.store_path(), {page: {"viewer": False}})
    assert ui_visibility.overrides() == {page: {"viewer": False}}
    assert not (tmp_path / "dashboard-ui-visibility.json").exists()
    assert list(saved_records(records_in_postgres)) == ["dashboard-ui-visibility.json"]
    _put(ui_visibility.store_path(), "{not json")
    assert ui_visibility.overrides() == {}


def test_account_names_are_kept_in_postgres(records_in_postgres, tmp_path, monkeypatch):
    from maverick_dashboard import account_profiles

    monkeypatch.setenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", "1")
    account_profiles.record_sign_in("user:u1", {"name": "Ada Lovelace"})
    assert account_profiles._read()["user:u1"]["name"] == "Ada Lovelace"
    assert not (tmp_path / "account-profiles.json").exists()
    assert list(saved_records(records_in_postgres)) == ["account-profiles.json"]
    account_profiles.record_sign_in("user:u1", {})
    assert account_profiles._read() == {}


def test_subjects_and_retired_subjects_are_kept_in_postgres(records_in_postgres, tmp_path):
    from maverick_dashboard import subject_directory as sd

    retired_key = sd._key("gone@example.com")
    _put(sd._retired_path(), {"subjects": {sd._key("old-sub"): 1.0, retired_key: 2.0}})
    sd.record_login("sub-1", ["Ada@Example.com", "gone@example.com"], at=100.0)
    assert sd.subject_for("ada@example.com") == "sub-1"
    assert sd._subject_key("sub-1") in sd._load_retired()  # the tombstone carried over
    assert not list(tmp_path.glob("oidc-*"))
    assert set(saved_records(records_in_postgres)) == {"oidc-subjects.json", "oidc-retired-subjects.json"}


def test_a_corrupt_subject_record_in_postgres_is_refused(records_in_postgres):
    from maverick_dashboard import subject_directory as sd

    _put(sd._path(), "{not json")
    with pytest.raises(sd.SubjectDirectoryError):
        sd.subject_for("ada@example.com")
    _put(sd._path(), json.dumps({"a" * 64: {"sub": "x", "ts": 1}}) + " " * (sd._MAX_STORE_CHARS + 1))
    with pytest.raises(sd.SubjectDirectoryError):
        sd.subject_for("ada@example.com")


def test_a_revoked_session_is_still_refused_in_postgres(records_in_postgres, tmp_path):
    from maverick_dashboard import session_revocation as sr

    sr.revoke_principal("user:eve", at=100.0)
    sr.revoke_principal("user:eve", at=50.0)
    assert sr.revocation_epoch("user:eve") == 100.0
    assert sr.is_revoked("user:eve", issued_at=99.0) is True
    assert sr.is_revoked("user:eve", issued_at=100.0) is False
    assert sr.is_revoked("user:eve", issued_at=None) is True
    assert sr.is_revoked("user:someone-else", issued_at=1.0) is False
    assert not (tmp_path / "session-revocations.json").exists()
    assert list(saved_records(records_in_postgres)) == ["session-revocations.json"]


def test_a_corrupt_revocation_record_in_postgres_refuses_every_session(records_in_postgres):
    from maverick_dashboard import session_revocation as sr

    _put(sr._path(), "{not json")
    with pytest.raises(sr.RevocationStoreError):
        sr.revocation_epoch("user:eve")
    assert sr.is_revoked("user:eve", issued_at=9e12) is True


def test_account_names_stay_encrypted_in_postgres_when_encryption_is_on(records_in_postgres, tmp_path, monkeypatch):
    """The file was sealed with the deployment key when at-rest encryption is on;
    the database row must be too, not plain text."""
    from maverick import crypto_at_rest
    from maverick_dashboard import account_profiles

    monkeypatch.setenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert crypto_at_rest.deployment_at_rest_enabled()
    account_profiles.record_sign_in("user:u1", {"name": "Ada Lovelace"})
    stored = saved_records(records_in_postgres)["account-profiles.json"]
    assert "Ada Lovelace" not in stored and crypto_at_rest.is_sealed_str(stored)
    assert account_profiles._read()["user:u1"]["name"] == "Ada Lovelace"


def test_postgres_roster_reads_roles_and_presence_together(records_in_postgres, monkeypatch):
    from maverick import record_documents
    from maverick_dashboard import rbac

    _put(rbac.store_path(), {"alice": "operator"})
    assert rbac.list_users() == {"alice": "operator"}  # write the existing presence marker
    run = record_documents._run
    selects = []

    def counted(cursor, statement, parameters):
        if statement.startswith("SELECT"):
            selects.append(statement)
        return run(cursor, statement, parameters)

    monkeypatch.setattr(record_documents, "_run", counted)
    assert rbac.get_stored_role("alice") == "operator"
    assert len(selects) == 1
    assert not rbac.store_path().exists()
    assert "dashboard-users.json" in saved_records(records_in_postgres)
