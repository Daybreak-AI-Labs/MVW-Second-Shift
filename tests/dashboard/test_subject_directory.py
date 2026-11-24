"""Login-time OIDC subject directory: bridges IdP identifiers to the session
``sub`` so SCIM deprovision can revoke a pairwise-``sub`` session (Entra)."""
from __future__ import annotations

import pytest

from maverick_dashboard import subject_directory as sd


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_raw_identifiers_never_hit_disk():
    # Privacy: lookup keys are hashed; the raw email must not appear in the file.
    sd.record_login("s1", ["secret.person@example.com"])
    raw = sd._path().read_text(encoding="utf-8")
    assert "secret.person@example.com" not in raw
    assert "example.com" not in raw
    # The opaque sub (the revocation key, not PII) is stored.
    assert "s1" in raw
