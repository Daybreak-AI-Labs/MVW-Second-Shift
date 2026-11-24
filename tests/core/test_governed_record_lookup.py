"""Canonical hydration, bounded migration and actual interrupted local writes."""
from __future__ import annotations

import pytest
from maverick.governed_record_lookup import RecordLookupSpec, RecordLookupUnavailable, lookup_digest
from maverick.governed_records import LocalGovernedRecordBackend, RecordConflict


def keys(row):
    return [lookup_digest(token) for token in row.get("tokens", [])]


SPEC = RecordLookupSpec("test-tokens-v1", keys)


@pytest.fixture
def backend(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    return LocalGovernedRecordBackend("lookup_test", "LRB", lookup_spec=SPEC)


def test_warm_lookup_hydrates_one_source_and_invalid_token_reads_no_bodies(backend, monkeypatch):
    for index in range(25):
        backend.save({"id": f"LRB-{index:04d}", "tokens": [f"token-{index}"]})
    assert backend.maintain_lookup()["ready"]
    original, calls = backend._store.load, []
    def counted(record_id):
        calls.append(record_id)
        return original(record_id)
    monkeypatch.setattr(backend._store, "load", counted)
    monkeypatch.setattr(backend._store, "list", lambda: pytest.fail("full scan"))
    assert backend.lookup(lookup_digest("token-0"))["id"] == "LRB-0000"
    assert calls == ["LRB-0000"]
    calls.clear()
    assert backend.lookup(lookup_digest("missing")) is None
    assert not calls


def test_legacy_migration_is_bounded_resumes_and_never_false_404(backend, monkeypatch):
    for index in range(27):
        backend._store.save({"id": f"LRB-{index:04d}", "tokens": [f"token-{index}"]})
    original, calls = backend._store.load, []
    def counted(record_id):
        calls.append(record_id)
        return original(record_id)
    monkeypatch.setattr(backend._store, "load", counted)
    with pytest.raises(RecordLookupUnavailable, match="rebuilding"):
        backend.lookup(lookup_digest("token-26"))
    assert len(calls) == 10
    progress = backend.maintain_lookup(limit=3)
    assert not progress["ready"] and progress["scanned"] == 13
    # A fresh object uses the durable cursor rather than beginning again.
    restarted = LocalGovernedRecordBackend("lookup_test", "LRB", lookup_spec=SPEC)
    assert restarted.maintain_lookup(limit=3)["scanned"] == 16
    assert restarted.maintain_lookup()["ready"]
    for index in (0, 13, 26):
        assert restarted.lookup(lookup_digest(f"token-{index}"))["id"] == f"LRB-{index:04d}"


def test_replace_delete_collision_and_cas_keep_projection_consistent(backend):
    saved = backend.save({"id": "LRB-one", "tokens": ["old"]})
    newer = backend.update("LRB-one", lambda row: row.update(tokens=["new"]), expected_revision=saved["revision"])
    with pytest.raises(RecordConflict):
        backend.update("LRB-one", lambda row: row.update(tokens=["stale"]), expected_revision=saved["revision"])
    assert backend.lookup(lookup_digest("old")) is None
    assert backend.lookup(lookup_digest("new"))["revision"] == newer["revision"]
    other = backend.save({"id": "LRB-two", "tokens": ["new"]})
    with pytest.raises(RecordLookupUnavailable, match="ambiguous"):
        backend.lookup(lookup_digest("new"))
    assert backend.delete("LRB-two", expected_revision=other["revision"])
    assert backend.lookup(lookup_digest("new"))["id"] == "LRB-one"


def test_restore_marker_forces_rebuild_and_invalid_source_is_not_published(backend):
    backend.save({"id": "LRB-one", "tokens": ["kept"]})
    assert backend.lookup(lookup_digest("kept"))
    from maverick.file_lock import atomic_write_text
    marker = backend._store._dir() / ".record-lookup-rebuild"
    atomic_write_text(marker, "rebuild\n")
    assert backend.maintain_lookup()["ready"] and not marker.exists()
    with pytest.raises(RecordLookupUnavailable, match="key bound"):
        backend.update("LRB-one", lambda row: row.update(tokens=[str(i) for i in range(21)]))
    assert backend.lookup(lookup_digest("kept"))["revision"] == 1


def test_corrupt_index_requires_explicit_rebuild(backend):
    backend.save({"id": "LRB-one", "tokens": ["kept"]})
    from maverick.file_lock import atomic_write_bytes
    path = backend._store._dir() / ".record-lookup" / (SPEC.name + ".sqlite3")
    atomic_write_bytes(path, b"invalid SQLite")
    with pytest.raises(RecordLookupUnavailable, match="explicit rebuild"):
        backend.lookup(lookup_digest("kept"))
    assert backend.maintain_lookup(rebuild=True)["ready"]
    assert backend.lookup(lookup_digest("kept"))


def test_explicit_rebuild_recovers_derived_schema_drift(backend):
    import sqlite3
    backend.save({"id": "LRB-one", "tokens": ["kept"]})
    path = backend._store._dir() / ".record-lookup" / (SPEC.name + ".sqlite3")
    with sqlite3.connect(str(path)) as connection:
        connection.execute("ALTER TABLE state DROP COLUMN signature")
    assert backend.maintain_lookup(rebuild=True)["ready"]
    assert backend.lookup(lookup_digest("kept"))["id"] == "LRB-one"
