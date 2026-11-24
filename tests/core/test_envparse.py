"""Tests for environment-variable parsing (maverick._envparse)."""
from __future__ import annotations


def test_env_bool(monkeypatch):
    from maverick._envparse import env_bool
    monkeypatch.setenv("X_EB", "on")
    assert env_bool("X_EB") is True
    monkeypatch.setenv("X_EB", "OFF")
    assert env_bool("X_EB") is False
    monkeypatch.setenv("X_EB", "garbage")
    assert env_bool("X_EB", True) is True
    monkeypatch.delenv("X_EB")
    assert env_bool("X_EB", False) is False


def test_is_truthy():
    from maverick._envparse import is_truthy
    for v in ("1", "true", "TRUE", "Yes", " on "):
        assert is_truthy(v) is True
    for v in ("0", "false", "no", "off", "", "garbage", None):
        assert is_truthy(v) is False


def test_coerce_bool():
    from maverick._envparse import coerce_bool
    assert coerce_bool("yes") is True
    assert coerce_bool("off") is False
    assert coerce_bool(None) is False
    assert coerce_bool(None, True) is True
    # unrecognized string falls back to default, not Python truthiness
    assert coerce_bool("maybe", True) is True
    assert coerce_bool("maybe", False) is False
    # non-string types use Python truthiness
    assert coerce_bool(1) is True
    assert coerce_bool(0) is False
    assert coerce_bool(True) is True
