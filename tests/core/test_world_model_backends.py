"""Tests for world-model backend selection and the Postgres adapter
(maverick.world_model_backends).
"""
from __future__ import annotations


def test_postgres_is_configured_default_false(monkeypatch):
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-for-this-test")
    from maverick.world_model_backends import is_postgres_configured
    # No env, no config -> False.
    assert is_postgres_configured() is False


def test_postgres_is_configured_via_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    from maverick.world_model_backends import is_postgres_configured
    assert is_postgres_configured() is True


def test_postgres_is_configured_via_config(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir()
    (cfg_dir / "config.toml").write_text(
        '[world_model]\nbackend = "postgres"\n'
    )
    from maverick.world_model_backends import is_postgres_configured
    assert is_postgres_configured() is True


def test_postgres_schema_constants_exist():
    """The migration SQL list is present and has the expected tables."""
    from maverick.world_model_backends.postgres import SCHEMA
    joined = " ".join(SCHEMA)
    for tbl in ("goals", "episodes", "goal_events", "facts"):
        assert f"CREATE TABLE IF NOT EXISTS {tbl}" in joined
