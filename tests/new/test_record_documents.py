"""Named records: files in the data folder, or rows in Postgres."""
from __future__ import annotations

import json
import stat
import threading

import pytest

from tests.new.conftest import saved_records


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for name in ("MAVERICK_WORLD_BACKEND", "MAVERICK_PG_DSN"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


# -------------------------------------------------------------- files

def test_files_behave_as_before(home):
    from maverick import record_documents

    doc = record_documents.at(home / "sample.json")
    assert record_documents.using_postgres() is False
    assert doc.read_text() is None and doc.exists() is False
    with doc.locked():
        doc.write_text('{"a": 1}')
    assert (home / "sample.json").read_text() == '{"a": 1}'
    assert stat.S_IMODE((home / "sample.json").stat().st_mode) == 0o600
    assert doc.read_text() == '{"a": 1}' and doc.exists() is True


def test_a_record_is_text(home):
    from maverick import record_documents

    with pytest.raises(TypeError):
        record_documents.at(home / "sample.json").write_text(b"bytes")  # type: ignore[arg-type]


# ----------------------------------------------------------- Postgres

def test_postgres_keeps_records_out_of_the_data_folder(records_in_postgres, tmp_path):
    from maverick import record_documents

    doc = record_documents.at(tmp_path / "sample.json")
    assert record_documents.using_postgres() is True
    assert doc.read_text() is None and doc.exists() is False
    doc.write_text('{"a": 1}')
    assert doc.read_text() == '{"a": 1}' and doc.exists() is True
    assert not (tmp_path / "sample.json").exists()
    assert saved_records(records_in_postgres) == {"sample.json": '{"a": 1}'}


def test_postgres_keeps_tenants_apart_by_path(records_in_postgres, tmp_path):
    from maverick import record_documents

    record_documents.at(tmp_path / "sample.json").write_text("shared")
    record_documents.at(tmp_path / "tenants" / "t1" / "sample.json").write_text("tenant")
    assert saved_records(records_in_postgres) == {"sample.json": "shared", "tenants/t1/sample.json": "tenant"}


def test_postgres_change_inside_the_lock_commits_at_the_end(records_in_postgres, tmp_path):
    from maverick import record_documents

    doc = record_documents.at(tmp_path / "sample.json")
    with doc.locked():
        assert doc.read_text() is None
        doc.write_text("first")
        assert doc.read_text() == "first"  # the holder sees its own change
        assert saved_records(records_in_postgres) == {}  # others do not, yet
    assert saved_records(records_in_postgres) == {"sample.json": "first"}


def test_postgres_failure_inside_the_lock_undoes_the_change(records_in_postgres, tmp_path):
    from maverick import record_documents

    doc = record_documents.at(tmp_path / "sample.json")
    doc.write_text("kept")
    with pytest.raises(RuntimeError, match="stop"), doc.locked():
        doc.write_text("lost")
        raise RuntimeError("stop")
    assert doc.read_text() == "kept"


def test_postgres_lock_is_reentrant_in_one_context(records_in_postgres, tmp_path):
    from maverick import record_documents

    doc = record_documents.at(tmp_path / "sample.json")
    with doc.locked(), doc.locked():
        doc.write_text("inner")
    assert doc.read_text() == "inner"


def test_postgres_lock_serialises_concurrent_changes(records_in_postgres, tmp_path):
    from maverick import record_documents

    doc = record_documents.at(tmp_path / "counter.json")
    doc.write_text(json.dumps({"n": 0}))
    failures: list[BaseException] = []

    def bump(times: int) -> None:
        try:
            for _ in range(times):
                with doc.locked():
                    value = json.loads(doc.read_text() or "{}")["n"]
                    doc.write_text(json.dumps({"n": value + 1}))
        except BaseException as exc:  # noqa: BLE001 -- reported below
            failures.append(exc)

    threads = [threading.Thread(target=bump, args=(15,)) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert json.loads(doc.read_text() or "{}") == {"n": 60}


def test_postgres_refuses_a_path_outside_the_data_folder(records_in_postgres, tmp_path):
    from maverick import record_documents

    with pytest.raises(record_documents.RecordDocumentError):
        record_documents.at(tmp_path.parent / "elsewhere.json").read_text()


def test_unreachable_database_is_an_error_without_the_address(tmp_path, monkeypatch):
    """Configured but unreachable is a refusal, never a fallback to the folder,
    and the message does not carry the database address or its password."""
    pytest.importorskip("psycopg")
    from maverick import config, record_documents

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN",
                       "postgresql://someone:not-a-real-password@127.0.0.1:1/nothing?connect_timeout=2")  # pragma: allowlist secret
    config.reset_config_cache()
    record_documents._reset_for_tests()
    doc = record_documents.at(tmp_path / "sample.json")
    for attempt in (doc.read_text, lambda: doc.write_text("x")):
        with pytest.raises(OSError) as caught:
            attempt()
        assert "not-a-real-password" not in str(caught.value) and "127.0.0.1" not in str(caught.value)
    assert not (tmp_path / "sample.json").exists()
    record_documents._reset_for_tests()
    config.reset_config_cache()


def test_postgres_without_an_address_is_an_error(tmp_path, monkeypatch):
    from maverick import config, record_documents

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    config.reset_config_cache()
    with pytest.raises(record_documents.RecordDocumentError, match="no database address"):
        record_documents.at(tmp_path / "sample.json").read_text()
    config.reset_config_cache()
