from __future__ import annotations
from maverick.config import load_config


def test_explicit_load_config_path_ignores_environment_overlay(monkeypatch, tmp_path):
    base = tmp_path / "config.toml"
    base.write_text('[search]\nn = 1\n', encoding="utf-8")
    overlay = tmp_path / "overlay.toml"
    overlay.write_text('[search]\nn = 5\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(overlay))

    assert load_config(base) == {"search": {"n": 1}}
