"""The session and recorder stores have the same lifecycle in both databases."""
from __future__ import annotations

import time

import pytest


@pytest.fixture(params=["sqlite", "postgres"])
def mode(request, tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setenv("MAVERICK_PG_RLS", "1")
    from maverick import config

    config.reset_config_cache()
    if request.param == "sqlite":
        monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "sqlite")
        return None
    return request.getfixturevalue("records_in_postgres")


def _session(sid):
    from maverick_dashboard import session_registry

    now = time.time()
    session_registry.register(sid=sid, principal="user:employee", via="oidc", mfa=True, mfa_at=now,
                              issued_at=now, expires_at=now + 3600, ip="", user_agent="Chrome/")


def test_session_updates_and_revocation_are_visible(mode):
    from maverick_dashboard import session_registry as sessions

    sid = sessions.new_sid()
    _session(sid)
    assert sessions.current(sid, principal="user:someone-else") is None
    live = sessions.current(sid, principal="user:employee")
    assert live.mfa and live.user_agent == "Chrome"
    assert sessions.revoke(sid, by="user:employee").revoked_at
    assert sessions.current(sid, principal="user:employee") is None
    assert sessions._path().exists() is (mode is None)
    if mode:
        import psycopg

        with psycopg.connect(mode) as db:
            assert db.execute("SELECT sid FROM sessions").fetchone() == (sid,)


def test_device_key_replacement_binding_and_workspace(mode):
    from maverick import ekko_device_keys as keys

    params = {"tenant": "alpha"}
    key, record = keys.create("person", "desk", enrollment="test", **params)
    assert keys.find(key).key_id == record.key_id
    assert keys.for_device("person", "desk", tenant="beta") is None
    assert keys.for_device("other", "desk", **params) is None
    assert keys.bind_account(record, "a" * 64)
    assert not keys.bind_account(record, "b" * 64)
    new_key, new_record = keys.create("person", "desk", enrollment="test", **params)
    assert keys.find(key) is None
    assert keys.find(new_key).key_id == new_record.key_id
    assert keys.revoke("person", "desk", **params)
    assert keys.find(new_key) is None
    assert keys._path().exists() is (mode is None)


def test_existing_browser_sessions_survive_postgres_upgrade(records_in_postgres, monkeypatch):
    from maverick_dashboard import session_registry as sessions

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "sqlite")
    sid = sessions.new_sid()
    _session(sid)
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    assert sessions.current(sid, principal="user:employee")
    assert sessions.revoke(sid, by="user:employee").revoked_at
    assert sessions.current(sid, principal="user:employee") is None
    import psycopg

    with psycopg.connect(records_in_postgres) as db:
        assert db.execute("SELECT revoked_at FROM sessions WHERE sid=%s", (sid,)).fetchone()[0]


def test_recorder_keys_remain_encrypted_after_import(records_in_postgres, monkeypatch):
    import psycopg

    from maverick import ekko_device_keys as keys

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "sqlite")
    key, record = keys.create("private person", "desk", tenant="alpha", enrollment="test")
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    assert keys.find(key).key_id == record.key_id
    with psycopg.connect(records_in_postgres) as db:
        sealed, digest = db.execute("SELECT record,key_hash FROM ekko_device_keys").fetchone()
    assert b"private person" not in sealed
    assert key.encode() not in sealed
    assert digest == keys.hash_key(key)
    assert keys.revoke("private person", "desk", tenant="alpha")
    assert keys.find(key) is None


def test_ekko_private_consent_session_and_erasure(mode):
    from maverick.work_discovery import CapturePolicy
    from maverick.work_discovery_store import WorkDiscoveryStore

    policy = CapturePolicy(enabled=True, allowed_apps=frozenset({"excel"}))
    store = WorkDiscoveryStore("person", "desk", tenant="alpha", authority_check=lambda _: None)
    store.enroll(policy)
    session = store.create_session(policy=policy)
    other = WorkDiscoveryStore("other", "desk", tenant="alpha")
    assert other.get_session(session.session_id) is None
    assert other.get_enrollment() is None
    assert WorkDiscoveryStore("person", "desk", tenant="beta").get_session(session.session_id) is None
    assert store.get_session(session.session_id).session_id == session.session_id
    assert store.erase(session_id=session.session_id)["sessions"] == 1
    assert store.get_session(session.session_id) is None
    assert store.path.exists() is (mode is None)
    if mode:
        import psycopg

        with psycopg.connect(mode) as db:
            assert db.execute("SELECT count(*) FROM ekko_enrollments").fetchone() == (1,)


def test_ekko_legacy_session_is_copied_only_once(records_in_postgres, monkeypatch):
    from maverick.work_discovery import CapturePolicy
    from maverick.work_discovery_store import WorkDiscoveryStore

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "sqlite")
    policy = CapturePolicy(enabled=True, allowed_apps=frozenset({"excel"}))
    store = WorkDiscoveryStore("person", "desk", tenant="alpha", authority_check=lambda _: None)
    store.enroll(policy)
    session = store.create_session(policy=policy)

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    assert store.get_session(session.session_id) == session
    assert store.erase(session_id=session.session_id)["sessions"] == 1
    assert store.get_session(session.session_id) is None


def test_postgres_forces_scope_before_showing_any_saved_rows(records_in_postgres):
    import uuid

    import psycopg
    from psycopg import sql

    from maverick import ekko_device_keys, postgres_scoped_sql
    from maverick.work_discovery import CapturePolicy
    from maverick.work_discovery_store import WorkDiscoveryStore
    from maverick_dashboard import session_registry

    sid = session_registry.new_sid()
    _session(sid)
    key, _ = ekko_device_keys.create("person", "desk", tenant="alpha", enrollment="test")
    store = WorkDiscoveryStore("person", "desk", tenant="alpha", authority_check=lambda _: None)
    store.enroll(CapturePolicy(enabled=True, allowed_apps=frozenset({"excel"})))
    reader = sql.Identifier("scoped_reader_" + uuid.uuid4().hex)
    with psycopg.connect(records_in_postgres) as db:
        with db.cursor() as cur:
            cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOBYPASSRLS").format(reader))
            cur.execute(sql.SQL("GRANT SELECT ON sessions,ekko_device_keys,ekko_enrollments TO {}").format(reader))
            cur.execute(sql.SQL("SET LOCAL ROLE {}").format(reader))
            for table in ("sessions", "ekko_device_keys", "ekko_enrollments"):
                assert cur.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone() == (0,)
            postgres_scoped_sql.bind(cur, postgres_scoped_sql.workspace_key("beta"))
            assert cur.execute("SELECT count(*) FROM ekko_device_keys").fetchone() == (0,)
            postgres_scoped_sql.bind(cur, "", ekko_device_keys.hash_key(key))
            assert cur.execute("SELECT count(*) FROM ekko_device_keys").fetchone() == (1,)
            postgres_scoped_sql.bind(cur, store._tenant_key)
            assert cur.execute("SELECT count(*) FROM ekko_enrollments").fetchone() == (1,)
            postgres_scoped_sql.bind(cur, session_registry._session_workspace())
            assert cur.execute("SELECT sid FROM sessions").fetchone() == (sid,)
        db.rollback()


def test_postgres_refuses_unavailable_records_without_falling_back(records_in_postgres, monkeypatch):
    from psycopg.conninfo import make_conninfo

    from maverick import ekko_device_keys
    from maverick.work_discovery_store import WorkDiscoveryStore, WorkDiscoveryStoreError
    from maverick_dashboard import session_registry

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "sqlite")
    sid = session_registry.new_sid()
    _session(sid)
    key, _ = ekko_device_keys.create("person", "desk", tenant="alpha", enrollment="test")
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", make_conninfo(records_in_postgres, port=1, connect_timeout=1))
    with pytest.raises(session_registry.SessionStoreError):
        session_registry.current(sid, principal="user:employee")
    with pytest.raises(ekko_device_keys.DeviceKeyError):
        ekko_device_keys.find(key)
    with pytest.raises(WorkDiscoveryStoreError):
        WorkDiscoveryStore("person", "desk", tenant="alpha").get_enrollment()
