"""[auth.mfa], [auth.ip_allowlist] and [auth.sessions] knobs: defaults,
config values, environment overrides and fail-closed handling of bad values."""
from __future__ import annotations

import pytest

from maverick import config


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_MFA_REQUIRE", "MAVERICK_MFA_STEP_UP_MINUTES",
                 "MAVERICK_IP_ALLOWLIST"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _write(tmp_path, text: str) -> None:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def test_bad_values_fail_closed_or_fall_back(tmp_path):
    _write(tmp_path, "[auth.mfa]\nrequire = \"maybe\"\nstep_up_minutes = \"soon\"\n"
                     "amr_values = \"otp, sms\"\n[auth.sessions]\nretention_days = -4\n")
    mfa = config.get_auth_mfa()
    assert mfa["require"] is True            # a non-bool security switch counts as on
    assert mfa["step_up_minutes"] == 15      # nonsense: the documented default
    assert mfa["amr_values"] == ["otp", "sms"]  # a comma string is tolerated
    assert config.get_auth_sessions()["retention_days"] == 1


@pytest.mark.parametrize("line", ["company_hours = 169", "idle_minutes = -1",
                                  "idle_minutes = true", "company_hours = \"8\""])
def test_bad_session_limits_fail_closed(tmp_path, line):
    _write(tmp_path, "[auth.sessions]\n" + line + "\n")
    with pytest.raises(ValueError, match="auth.sessions"):
        config.get_auth_sessions()


def test_session_limits_fail_closed_when_the_source_breaks_during_the_load(tmp_path, monkeypatch):
    # The check before the load sees a clean file; the file breaks just before
    # the load reads it. The defaults must not be used in its place.
    _write(tmp_path, "[auth.sessions]\ncompany_hours = 8\n")
    assert config.get_auth_sessions()["company_hours"] == 8
    real_load = config.load_global_config

    def load_after_the_file_breaks():
        (tmp_path / "home" / "config.toml").write_text("[auth.sessions\n", encoding="utf-8")
        return real_load()

    monkeypatch.setattr(config, "load_global_config", load_after_the_file_breaks)
    with pytest.raises(ValueError, match="Sign-in settings cannot be read"):
        config.get_auth_sessions()


@pytest.mark.parametrize("value", ["inf", "-inf", "1e999", "nan"])
def test_an_unusable_step_up_window_falls_back_to_the_default(tmp_path, value):
    _write(tmp_path, f"[auth.mfa]\nrequire = true\nstep_up_minutes = {value}\n")
    mfa = config.get_auth_mfa()  # must not raise: a raise reads as "policy unreadable" and locks everyone out
    assert mfa["require"] is True and mfa["step_up_minutes"] == config.DEFAULT_STEP_UP_MINUTES


def test_an_unusable_step_up_window_in_the_environment_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("MAVERICK_MFA_STEP_UP_MINUTES", "1e999")
    assert config.get_auth_mfa()["step_up_minutes"] == config.DEFAULT_STEP_UP_MINUTES
