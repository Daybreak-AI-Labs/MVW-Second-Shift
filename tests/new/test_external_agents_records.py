"""The enrollment record with Postgres: enrolling an agent keeps its record
(and its trust entry) in the database, and an unreadable row is refused."""
from __future__ import annotations

import pytest

from maverick import external_agents as xa
from tests.new.conftest import saved_records


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _enroll():
    return xa.enroll("sf-quotebot", "agentforce", description="quoting agent",
                     owner="jordan@corp.test", department="sales", max_risk="medium",
                     max_dollars=5.0, enrolled_by="admin@corp.test",
                     allow_tools=["crm_update:low", "research:low"])


def test_with_postgres_an_enrollment_is_kept_there(tmp_path, records_in_postgres):
    _enroll()

    meta = xa._load_sidecar(strict=True)["sf-quotebot"]
    assert meta["platform"] == "agentforce"
    assert not (tmp_path / "external_agents.json").exists()
    assert not (tmp_path / "agent_trust.json").exists()
    keys = saved_records(records_in_postgres)
    assert "external_agents.json" in keys
    assert "agent_trust.json" in keys


def test_with_postgres_an_unreadable_enrollment_record_is_refused(records_in_postgres):
    import psycopg

    _enroll()
    with psycopg.connect(records_in_postgres) as connection:
        connection.execute("UPDATE second_shift_records SET body = %s WHERE key = %s",
                           ("{not json", "external_agents.json"))
    with pytest.raises(xa.ExternalAgentsDependencyError):
        xa._load_sidecar(strict=True)
    with pytest.raises(xa.ExternalAgentsDependencyError):
        xa._save_sidecar({"x": {}})
