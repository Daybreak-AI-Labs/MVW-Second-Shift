"""Role-based UI visibility: the page registry, the admin override store, the
role-filtered sidebar, and the page-level enforcement dependency.

Safety invariants under test (mirror maverick_dashboard.rbac's):
  * auth OFF (no principal) -> full nav, nothing enforced (single-user mode);
  * overrides can never show a page past the role's permission floor;
  * admins can never lose /settings or /users (lockout guard);
  * page policy governs UI pages only -- /api routes are untouched.
"""
from __future__ import annotations


def test_agent_control_plane_read_surface_is_discoverable_to_auditors():
    from maverick_dashboard import ui_visibility

    page = next(
        item for item in ui_visibility.PAGES
        if item["path"] == "/agent-control-plane"
    )
    assert page["floor"] == "view"
    assert page["default"] == "view"
    assert ui_visibility.is_visible(page, "auditor") is True
