"""The name and verified email a sign-in reports, so people read as people.

Live: approvals, settings history and the Activity log named the installation
administrator only as "Google account", because nothing kept the name the
identity provider reported. The account record keeps only the verified email
and display name, follows the at-rest encryption setting, is in My data's
export and is removed by My data's reviewed deletion and the company
directory's account deletion.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.fixture
def profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", raising=False)
    from maverick_dashboard import account_profiles

    return account_profiles


def test_oidc_sign_in_records_the_account(profiles, monkeypatch):
    from maverick_dashboard import oidc_login

    seen = []
    monkeypatch.setattr(profiles, "record_sign_in", lambda principal, claims: seen.append((principal, claims)))
    oidc_login._remember_account(SimpleNamespace(sub="google-oauth2|1", claims={"name": "Dana Lee"}))
    assert seen == [("user:google-oauth2|1", {"name": "Dana Lee"})]
