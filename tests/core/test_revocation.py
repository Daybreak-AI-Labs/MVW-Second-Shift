"""Capability revocation list: registry behavior + the tool-chokepoint gate."""
from __future__ import annotations

import threading

import pytest

from maverick.file_lock import private_path_is_restricted
from maverick.revocation import (
    ProtectedRevocationError,
    RevocationGenerationMismatch,
    RevocationRegistry,
    RevocationStoreError,
)


def test_revoke_and_is_revoked(tmp_path):
    reg = RevocationRegistry(tmp_path / "rev.json")
    assert reg.is_revoked("agent:x") is False
    reg.revoke("agent:x", reason="leaked key")
    assert reg.is_revoked("agent:x") is True
    assert reg.revoked()["agent:x"].reason == "leaked key"


def test_unrevoke(tmp_path):
    reg = RevocationRegistry(tmp_path / "rev.json")
    reg.revoke("agent:x")
    assert reg.unrevoke("agent:x") is True
    assert reg.is_revoked("agent:x") is False
    assert reg.unrevoke("agent:x") is False  # already gone


def test_protected_containment_requires_explicit_release(tmp_path):
    reg = RevocationRegistry(tmp_path / "rev.json")
    contained = reg.revoke(
        "agent:x", reason="soc: honeytoken", now=10, protected=True,
    )
    with pytest.raises(ProtectedRevocationError, match="security-contained"):
        reg.unrevoke("agent:x")
    assert reg.revoked()["agent:x"] == contained
    with pytest.raises(ProtectedRevocationError, match="generation"):
        reg.unrevoke("agent:x", allow_protected=True)
    assert reg.unrevoke(
        "agent:x",
        allow_protected=True,
        expected_generation=contained.generation,
    ) is True
    assert not reg.is_revoked("agent:x")


def test_stale_protected_release_preserves_new_generation_and_skips_callback(tmp_path):
    reg = RevocationRegistry(tmp_path / "rev.json")
    first = reg.revoke(
        "agent:x", reason="incident one", now=10, protected=True,
    )
    second = reg.revoke(
        "agent:x", reason="incident two", now=20, protected=True,
    )
    callbacks = []

    with pytest.raises(RevocationGenerationMismatch, match="newer"):
        reg.unrevoke(
            "agent:x",
            allow_protected=True,
            expected_generation=first.generation,
            durable_clear=lambda: callbacks.append("cleared"),
        )

    assert callbacks == []
    assert first.generation and second.generation
    assert first.generation != second.generation
    assert reg.revoked()["agent:x"] == second


def test_protected_release_refuses_degraded_cross_process_lock(
    tmp_path, monkeypatch,
):
    from contextlib import contextmanager

    from maverick import file_lock

    reg = RevocationRegistry(tmp_path / "rev.json")
    contained = reg.revoke("agent:x", protected=True)

    @contextmanager
    def _degraded(_path, *, strict=False):
        assert strict is True
        raise RuntimeError("cross-process lock backend is unavailable")
        yield  # pragma: no cover

    monkeypatch.setattr(file_lock, "cross_process_lock", _degraded)
    with pytest.raises(RuntimeError, match="cross-process lock"):
        reg.unrevoke(
            "agent:x",
            allow_protected=True,
            expected_generation=contained.generation,
        )
    assert reg.revoked()["agent:x"] == contained


def test_ordinary_revoke_cannot_repaint_protected_provenance(tmp_path):
    reg = RevocationRegistry(tmp_path / "rev.json")
    contained = reg.revoke(
        "agent:x", reason="soc: original incident", now=10, protected=True,
    )
    assert reg.revoke(
        "agent:x", reason="operator: ordinary suspend", now=20,
    ) == contained
    assert reg.revoked()["agent:x"] == contained
    reg.revoke_subtree(
        "agent:x", {"agent:x": ["agent:child"]},
        reason="operator: subtree suspend", now=30,
    )
    assert reg.revoked()["agent:x"] == contained
    assert reg.revoked()["agent:child"].protected is False


def test_contain_racing_ordinary_unrevoke_never_loses_protection(tmp_path):
    path = tmp_path / "rev.json"
    failures: list[BaseException] = []
    start = threading.Barrier(3)

    def _contain() -> None:
        try:
            start.wait(timeout=5)
            RevocationRegistry(path).revoke(
                "agent:x", reason="soc incident", protected=True,
            )
        except BaseException as exc:  # captured for the assertion thread
            failures.append(exc)

    def _ordinary_resume() -> None:
        try:
            start.wait(timeout=5)
            try:
                RevocationRegistry(path).unrevoke("agent:x")
            except ProtectedRevocationError:
                pass
        except BaseException as exc:  # captured for the assertion thread
            failures.append(exc)

    threads = [threading.Thread(target=_contain), threading.Thread(target=_ordinary_resume)]
    for thread in threads:
        thread.start()
    start.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert failures == []
    record = RevocationRegistry(path).revoked()["agent:x"]
    assert record.protected is True
    assert record.reason == "soc incident"


def test_blank_principal_never_revoked(tmp_path):
    assert RevocationRegistry(tmp_path / "rev.json").is_revoked("") is False


def test_persisted_across_instances(tmp_path):
    p = tmp_path / "rev.json"
    RevocationRegistry(p).revoke("agent:x")
    assert RevocationRegistry(p).is_revoked("agent:x") is True


def test_reread_on_file_change_propagates(tmp_path):
    # The "propagation to running agents" property: one instance picks up
    # another process's revoke because the file mtime changed.
    p = tmp_path / "rev.json"
    running = RevocationRegistry(p)
    other = RevocationRegistry(p)
    assert running.is_revoked("agent:x") is False  # loads (empty)
    other.revoke("agent:x")                         # "another process"
    assert running.is_revoked("agent:x") is True    # re-read on mtime change


def test_corrupt_file_fails_closed(tmp_path):
    p = tmp_path / "rev.json"
    p.write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(RevocationStoreError, match="corrupt"):
        RevocationRegistry(p).is_revoked("agent:x")


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        '{"agent:x": null}',
        '{"agent:x": {"revoked_at": "yesterday"}}',
        '{"agent:x": {"revoked_at": NaN}}',
        '{"agent:x": {"revoked_at": 1, "reason": []}}',
        '{"agent:x": {"revoked_at": 1, "protected": "yes"}}',
        '{"agent:x": {"revoked_at": 1}, "agent:x": {"revoked_at": 2}}',
    ],
)
def test_malformed_registry_records_fail_closed(tmp_path, payload):
    p = tmp_path / "rev.json"
    p.write_text(payload, encoding="utf-8")
    with pytest.raises(RevocationStoreError, match="corrupt"):
        RevocationRegistry(p).is_revoked("agent:x")


def test_legacy_record_without_protected_flag_remains_ordinary(tmp_path):
    path = tmp_path / "rev.json"
    path.write_text(
        '{"agent:x": {"revoked_at": 1, "reason": "legacy"}}',
        encoding="utf-8",
    )
    reg = RevocationRegistry(path)
    assert reg.revoked()["agent:x"].protected is False
    assert reg.unrevoke("agent:x") is True


def test_legacy_protected_record_can_be_released_by_its_empty_generation(tmp_path):
    path = tmp_path / "rev.json"
    path.write_text(
        '{"agent:x": {"revoked_at": 1, "reason": "legacy", '
        '"protected": true}}',
        encoding="utf-8",
    )
    reg = RevocationRegistry(path)
    assert reg.revoked()["agent:x"].generation == ""
    assert reg.unrevoke(
        "agent:x", allow_protected=True, expected_generation="",
    ) is True


def test_unreadable_registry_fails_closed(tmp_path, monkeypatch):
    import maverick.revocation as R

    p = tmp_path / "rev.json"
    p.write_text("{}", encoding="utf-8")

    def _unreadable(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(R, "_bounded_read_text", _unreadable)
    with pytest.raises(RevocationStoreError, match="unreadable"):
        RevocationRegistry(p).is_revoked("agent:x")


def test_oversize_registry_fails_closed_before_unbounded_read(
    tmp_path, monkeypatch,
):
    import maverick.revocation as R

    monkeypatch.setattr(R, "_MAX_STORE_BYTES", 32)
    p = tmp_path / "rev.json"
    p.write_bytes(b"x" * 33)

    with pytest.raises(RevocationStoreError, match="exceeds 32 bytes"):
        RevocationRegistry(p).is_revoked("agent:x")


def test_too_many_registry_entries_fail_closed(tmp_path, monkeypatch):
    import maverick.revocation as R

    monkeypatch.setattr(R, "_MAX_ENTRIES", 1)
    p = tmp_path / "rev.json"
    p.write_text(
        '{"agent:a":{"revoked_at":1},"agent:b":{"revoked_at":2}}',
        encoding="utf-8",
    )

    with pytest.raises(RevocationStoreError, match="exceeds 1 entries"):
        RevocationRegistry(p).is_revoked("agent:a")


@pytest.mark.parametrize("field", ["principal", "reason"])
def test_overlong_registry_fields_fail_closed(tmp_path, monkeypatch, field):
    import maverick.revocation as R

    if field == "principal":
        monkeypatch.setattr(R, "_MAX_PRINCIPAL_LENGTH", 4)
        payload = '{"agent:too-long":{"revoked_at":1}}'
    else:
        monkeypatch.setattr(R, "_MAX_REASON_LENGTH", 4)
        payload = '{"a":{"revoked_at":1,"reason":"too long"}}'
    p = tmp_path / "rev.json"
    p.write_text(payload, encoding="utf-8")

    with pytest.raises(RevocationStoreError, match="corrupt"):
        RevocationRegistry(p).is_revoked("a")


def test_operator_write_refuses_to_replace_corrupt_registry(tmp_path):
    p = tmp_path / "rev.json"
    damaged = b"{ not valid json"
    p.write_bytes(damaged)

    with pytest.raises(RevocationStoreError, match="corrupt"):
        RevocationRegistry(p).revoke("agent:x")

    assert p.read_bytes() == damaged


def test_operator_write_refuses_over_limit_values(tmp_path, monkeypatch):
    import maverick.revocation as R

    monkeypatch.setattr(R, "_MAX_REASON_LENGTH", 4)
    p = tmp_path / "rev.json"

    with pytest.raises(ValueError, match="reason"):
        RevocationRegistry(p).revoke("agent:x", reason="too long")

    assert not p.exists()


def test_entry_limit_refuses_write_without_losing_revocations(
    tmp_path, monkeypatch,
):
    import maverick.revocation as R

    monkeypatch.setattr(R, "_MAX_ENTRIES", 1)
    p = tmp_path / "rev.json"
    reg = RevocationRegistry(p)
    reg.revoke("agent:a")

    with pytest.raises(ValueError, match="exceeds 1 entries"):
        reg.revoke("agent:b")

    fresh = RevocationRegistry(p)
    assert fresh.is_revoked("agent:a") is True
    assert fresh.is_revoked("agent:b") is False


def test_file_is_0600(tmp_path):
    p = tmp_path / "rev.json"
    RevocationRegistry(p).revoke("agent:x")
    assert private_path_is_restricted(p, 0o600)


def test_revoke_subtree_walks_delegation_graph(tmp_path):
    # diamond + a cycle edge back to root: every reachable principal revoked,
    # cycle does not loop forever.
    edges = {"root": ["a", "b"], "a": ["c"], "b": ["c", "root"]}
    reg = RevocationRegistry(tmp_path / "rev.json")
    order = reg.revoke_subtree("root", edges, reason="rogue parent")
    assert set(order) == {"root", "a", "b", "c"}
    for pr in ("root", "a", "b", "c"):
        assert reg.is_revoked(pr)


def test_revoke_subtree_leaf_only(tmp_path):
    reg = RevocationRegistry(tmp_path / "rev.json")
    order = reg.revoke_subtree("leaf", {"root": ["leaf"]})  # leaf has no children
    assert order == ["leaf"]
    assert reg.is_revoked("leaf") and not reg.is_revoked("root")


def test_module_is_revoked_fails_closed(monkeypatch):
    import maverick.revocation as R

    def _boom():
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(R, "shared", _boom)
    assert R.is_revoked("agent:x") is True
    assert R.is_revoked("") is False


def test_module_revoked_principal_fails_closed(monkeypatch):
    import maverick.revocation as R

    def _boom():
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(R, "shared", _boom)
    assert R.revoked_principal(("agent:x", "user:alice")) == "agent:x"
    assert R.revoked_principal(()) is None


def test_shared_is_keyed_per_tenant(tmp_path, monkeypatch):
    # shared() must give each tenant (data-dir) its own registry so one
    # tenant's mtime-cached revocation set can't be served to another — even
    # when two tenants' files share the same st_mtime tick.
    import maverick.paths as P
    import maverick.revocation as R

    tenant_a = tmp_path / "a"
    tenant_b = tmp_path / "b"
    current = {"dir": tenant_a}

    def _data_dir(name):
        d = current["dir"]
        d.mkdir(parents=True, exist_ok=True)
        return d / name

    monkeypatch.setattr(P, "data_dir", _data_dir)
    R.reset_shared()

    reg_a = R.shared()
    assert reg_a is R.shared()  # same tenant -> same instance
    current["dir"] = tenant_b
    reg_b = R.shared()
    assert reg_b is not reg_a  # different tenant -> independent instance

    # A cross-tenant call must consult the right file: revoke only in A.
    current["dir"] = tenant_a
    R.shared().revoke("evil")
    current["dir"] = tenant_b
    assert R.shared().is_revoked("evil") is False
    R.reset_shared()
