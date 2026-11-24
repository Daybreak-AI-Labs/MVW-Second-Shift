"""Time-boxed containment with Postgres: the schedule is kept in the database,
and an unreadable schedule is refused."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from maverick import agent_control_plane as acp
from tests.new.conftest import saved_records


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, revocation
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.setenv("MAVERICK_CONTROL_PLANE", "1")
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.reset_config_cache()
    revocation.reset_shared()
    monkeypatch.setattr("maverick.world_model.open_world",
                        lambda *a, **k: SimpleNamespace(list_goals=lambda **kw: []))
    yield
    config.reset_config_cache()
    revocation.reset_shared()


def test_with_postgres_a_timeboxed_containment_is_kept_there_and_released(tmp_path, records_in_postgres):
    from maverick.revocation import is_revoked

    scheduled = acp.contain_timeboxed(
        "user:local", reason="bounded incident", release_after_seconds=60,
        idempotency_key="case-123", actor="soc")
    assert scheduled.result.ok is True
    assert [r["status"] for r in acp.timeboxed_containments()] == ["scheduled"]
    assert acp.sweep_timeboxed_releases(now=scheduled.release_at - 0.1) == []
    assert is_revoked("user:local")
    released = acp.sweep_timeboxed_releases(now=scheduled.release_at + 0.1, actor="timer")
    assert [o.ok for o in released] == [True]
    assert not is_revoked("user:local")
    assert not (tmp_path / "control_plane_timeboxes.json").exists()
    assert "control_plane_timeboxes.json" in saved_records(records_in_postgres)


def test_with_postgres_an_unreadable_schedule_is_refused(records_in_postgres):
    import psycopg

    acp.contain_timeboxed("user:local", reason="bounded incident", release_after_seconds=60,
                          idempotency_key="case-123")
    with psycopg.connect(records_in_postgres) as connection:
        connection.execute("UPDATE second_shift_records SET body = %s WHERE key = %s",
                           ("{not json", "control_plane_timeboxes.json"))
    with pytest.raises(acp.ControlPlaneDependencyError):
        acp.timeboxed_containments()
