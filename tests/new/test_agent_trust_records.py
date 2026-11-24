"""The trust registry with Postgres: an agent added to it is kept in the
database, and an unreadable row is refused."""
from __future__ import annotations

import pytest

from maverick import agent_trust
from tests.new.conftest import saved_records


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import config
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _entry():
    return {"id": "vega", "direction": "both", "max_risk": "medium",
            "max_dollars": 5.0, "deny_tools": ["shell"]}


def test_with_postgres_a_trusted_agent_is_kept_there(tmp_path, records_in_postgres):
    agent_trust.put_agent(_entry())
    assert "vega" in agent_trust.load_registry_strict()
    assert agent_trust.set_revoked("vega", True) is True
    assert agent_trust.load_registry_strict()["vega"].revoked is True
    assert not (tmp_path / "agent_trust.json").exists()
    assert "agent_trust.json" in saved_records(records_in_postgres)


def test_with_postgres_an_unreadable_trust_record_is_refused(records_in_postgres):
    import psycopg

    agent_trust.put_agent(_entry())
    with psycopg.connect(records_in_postgres) as connection:
        connection.execute("UPDATE second_shift_records SET body = %s WHERE key = %s",
                           ("{not json", "agent_trust.json"))
    with pytest.raises(agent_trust.AgentTrustError):
        agent_trust.load_registry_strict()
    with pytest.raises(agent_trust.AgentTrustError):
        agent_trust.put_agent(_entry())
