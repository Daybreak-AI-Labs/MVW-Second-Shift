"""Dashboard RBAC: the role store, role resolution, and gate enforcement.

Safety invariants under test:
  * auth OFF (no principal) -> every gate is a no-op (single-user local mode);
  * a config-pinned bootstrap admin is always admin (can't be locked out);
  * viewer is read-only, operator can run goals, only admin reaches settings/users.
"""
from __future__ import annotations


def test_roster_from_before_the_marker_is_recorded_on_first_read(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick_dashboard import auth, rbac

    path = rbac.store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"user:demoted": "viewer"}', encoding="utf-8")
    path.chmod(0o600)
    assert auth.role_for_principal("user:demoted") == "viewer"
    path.unlink()
    assert auth.role_for_principal("user:demoted") is None
