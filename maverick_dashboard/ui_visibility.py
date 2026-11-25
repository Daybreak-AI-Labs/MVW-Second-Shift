"""Role-based UI visibility: which dashboard pages each RBAC role sees.

Two deliberately distinct layers:

  * ``floor`` -- the page's hard *security* requirement, mirroring the
    permission the route itself enforces (``/audit`` requires "audit",
    ``/settings`` requires "admin", ...). Visibility overrides can NEVER
    unlock a page past its floor: a role whose permissions don't include the
    floor cannot be shown the page, so presentation policy can't outrun authz.
  * ``default`` -- the page's *presentation* default: which permission a role
    must hold to see the page out of the box. This is what keeps a viewer's
    sidebar to read-only pages and an operator's free of admin plumbing. An
    admin may override it per role (within the floor) from Settings.

Safety invariants (mirror ``maverick_dashboard.rbac``):
  * Auth OFF (role ``None``) -> everything visible, nothing enforced -- the
    local single-user operator stays omnipotent, exactly as before.
  * Admins can never lose ``/settings`` or ``/users`` (``LOCKED``): a bad
    matrix save must not be able to lock every admin out of the controls
    that would undo it.
  * The store is one GLOBAL control-plane file, never per-tenant:
    ``~/.maverick/dashboard-ui-visibility.json`` (0600, kept with the other
    records, ``maverick.record_documents``), shaped
    ``{path: {role: bool}}`` and holding only differences from the defaults,
    so un-overridden cells follow default changes across releases.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import rbac

# One registry drives the sidebar nav, the enforcement dependency, and the
# Settings matrix -- order here IS the nav order. ``floor`` mirrors the
# route-enforced gate ("view" when the GET route has none); ``default`` is the
# permission a role must hold to see the page before any admin override.
# ``in_nav: False`` keeps a page governed (enforced + in the Settings matrix)
# but out of the sidebar -- secondary composers/detail surfaces reached from a
# primary page's own links, so the nav stays one entry per job.
# ``scope: global`` uses the installation-wide role and permission in
# request navigation and HTTP admission, never a tenant-local role grant.
# ``module`` names the in-app module switch (``api._MODULE_SWITCHES``) whose
# gate turns the page into a "...is turned off" dead end; a tuple means the page
# is a dead end only while every listed switch is off. The sidebar uses it to
# keep people away from dead ends (see ``mark_switched_off``).
# ``ready: False`` marks a page that is not ready for customers -- an operator
# workbench of record ids, verification fingerprints and raw status documents,
# or a module that ships switched off with no in-app way to turn it on. Such a
# page keeps its route and its permission gate (engineers and tests reach it
# by URL) but is offered nowhere: not in the sidebar, not in the page finder,
# not in the Settings visibility matrix. Flip it back to ready when the page
# speaks to a non-technical user.
PAGES: tuple[dict, ...] = ({'path': '/',
  'label': 'Home',
  'aliases': 'Today What needs me',
  'group': 'Home',
  'icon': 'overview',
  'floor': 'view',
  'default': 'view'},
 {'path': '/approvals',
  'label': 'Approvals',
  'group': 'Govern',
  'icon': 'check',
  'floor': 'approve',
  'default': 'approve'},
 {'path': '/agent-control-plane',
  'label': 'Agent controls',
  'aliases': 'Agent Control Plane',
  'group': 'Govern',
  'icon': 'agents',
  'floor': 'view',
  'default': 'view'},
 {'path': '/external-agents',
  'label': 'Outside agents',
  'aliases': 'External Agents',
  'group': 'AI oversight',
  'icon': 'agents',
  'floor': 'view',
  'default': 'view',
  'module': 'external_agents'},
 {'path': '/my-agents',
  'label': 'My agents',
  'aliases': 'Agents I own Owner',
  'group': 'AI oversight',
  'icon': 'agents',
  'floor': 'view',
  'default': 'view',
  'module': 'external_agents'},
 {'path': '/models',
  'label': 'Models',
  'aliases': 'Model register Model drift',
  'group': 'AI oversight',
  'icon': 'agents',
  'floor': 'view',
  'default': 'view'},
 {'path': '/spend',
  'label': 'Spend',
  'aliases': 'Budgets Costs',
  'group': 'Costs & value',
  'icon': 'spend',
  'floor': 'view',
  'default': 'view'},
 {'path': '/audit',
  'label': 'Audit trail',
  'aliases': 'Activity log',
  'group': 'Govern',
  'icon': 'audit',
  'floor': 'audit',
  'default': 'audit'},
 {'path': '/ekko',
  'label': 'Discover work to automate',
  'aliases': 'Ekko',
  'group': 'Agents',
  'icon': 'agents',
  'floor': 'operate',
  'default': 'operate'},
 {'path': '/factory',
  'label': 'Agent factory',
  'aliases': 'Build an agent',
  'group': 'Agents',
  'icon': 'agents',
  'floor': 'view',
  'default': 'view'},
 {'path': '/settings',
  'label': 'Settings',
  'aliases': 'Configuration Options',
  'group': 'Admin',
  'icon': 'settings',
  'floor': 'admin',
  'default': 'admin'})

# Moderate sidebar declutter: keep a focused set of everyday destinations in the
# rail; fold the rest OUT of the sidebar (in_nav=False) while leaving them fully
# reachable in-page and by URL. One place to adjust the balance — move a path
# out of this set to bring its tab back. (Pages already in_nav=False in the
# registry above, e.g. builders reached from a parent page, are unaffected.)
_NAV_FOLD: frozenset[str] = frozenset(
    {
        # Operate — reached from Goals / Agent Factory / Workforce
        "/start",
        "/projects",
        "/roles",
        # Observe — analytical/advanced views reached from Overview & friends
        "/discovery",
        "/providers",
        "/benchmarks",
        "/flows/analytics",
        "/walkthroughs",
        "/facts",
        "/plan-tree-3d",
        # Govern — advanced governance surfaces
        "/simulate",
        "/compartments",
        "/replay",
        "/trust",
        # Extend — secondary catalogs
        "/store",
        "/templates",
        "/tools",
        "/styles",
        # Admin — rarely-touched plumbing
        "/cache",
        "/embed-demo",
    }
)
for _pg in PAGES:
    if _pg["path"] in _NAV_FOLD:
        _pg["in_nav"] = False

# Where each page lives in the job-named navigation ("areas", off by default:
# ``[dashboard] navigation``): its area and the section inside that area, kept
# beside the entries above (which other code and tests read whole). One area
# per page; "Account" and "Help" are the account and help menus, and
# "Ask" is the Ask button. Placement only -- who may open a page still comes
# from its floor and default above, never from its area.
PAGE_AREAS: dict[str, tuple[str, str]] = {
    "/my-data": ("Account", "My data"),
    "/account": ("Account", "Your account"),
    "/content-access": ("Evidence & audit", "Content access"),
    "/preferences": ("Account", "Preferences"),
    "/today": ("Home", "Home"),
    "/workflow-readiness": ("Settings", "Setup"),
    "/code": ("Work", "Code changes"),
    "/me": ("Home", "Home"),
    "/outcome-pilots": ("Work", "Workflows"),
    "/commitment-reviews": ("Work", "Commitment reviews"),
    "/decision-evidence": ("Work", "Shared decision reviews"),
    "/learning/recheck-rules": ("Agents", "Learning"),
    "/learning/distinctions": ("Agents", "Learning"),
    "/learning/work-restructuring": ("Agents", "Learning"),
    "/learning/portable-rules": ("Agents", "Learning"),
    "/learning/recovery-visibility": ("Agents", "Learning"),
    "/learning/rules-together": ("Agents", "Learning"),
    "/learning/request-program": ("Agents", "Learning"),
    "/learning/applicability": ("Agents", "Learning"),
    "/learning/rule-evolution": ("Agents", "Learning"),
    "/learning/acquisition": ("Agents", "Learning"),
    "/private-task-computation": ("Work", "Tasks"),
    "/research": ("Agents", "Learning"),
    "/project-reviews": ("Work", "Projects"),
    "/deliverable-bundles": ("Work", "Results"),
    "/task-handoffs": ("Work", "Tasks"),
    "/action-center": ("Work", "Approvals"),
    "/start": ("Home", "Home"),
    "/chat": ("Ask", "Ask"),
    "/companion": ("Ask", "My companion"),
    "/goals": ("Work", "Tasks"),
    "/work-details": ("Work", "Business details"),
    "/goal-builder": ("Ask", "Ask"),
    "/graph-editor": ("Work", "Tasks"),
    "/projects": ("Work", "Projects"),
    "/deliverables": ("Work", "Results"),
    "/agents": ("Agents", "Build an agent"),
    "/roles": ("Agents", "Workforce"),
    "/workforce": ("Agents", "Workforce"),
    "/starter-teams": ("Agents", "Workforce"),
    "/legal": ("Work", "Legal"),
    "/workflows": ("Work", "Workflows"),
    "/flows/designer": ("Work", "Workflows"),
    "/workflow-builder": ("Work", "Workflows"),
    "/automations": ("Work", "Automations"),
    "/fleets": ("Agents", "Workforce"),
    "/overview": ("Home", "Home"),
    "/ekko": ("Agents", "Discover work to automate"),
    "/oversight": ("Rules & safety", "Overview"),
    "/discovery": ("Rules & safety", "What Second Shift can do"),
    "/run-tree": ("Evidence & audit", "Task replay"),
    "/spend": ("Costs & value", "Spend"),
    "/savings": ("Costs & value", "Savings"),
    "/work-value": ("Costs & value", "Work value & opportunities"),
    "/shoring": ("Work", "Hand over a team's work"),
    "/billing": ("Costs & value", "Billing"),
    "/providers": ("Settings", "AI providers"),
    "/settings/local-ai": ("Settings", "AI providers"),
    "/settings/security-installation": ("Settings", "Advanced"),
    "/benchmarks": ("Settings", "Advanced"),
    "/perf": ("Settings", "Advanced"),
    "/flows/analytics": ("Work", "Workflows"),
    "/cortex": ("Agents", "Knowledge"),
    "/knowledge-access": ("Agents", "Knowledge"),
    "/learning": ("Agents", "Learning"),
    "/learning/approval-challenges": ("Agents", "Learning"),
    "/learning/instructions": ("Agents", "Learning"),
    "/learned": ("Agents", "Learning"),
    "/walkthroughs": ("Evidence & audit", "Task replay"),
    "/facts": ("Agents", "Knowledge"),
    "/plan-tree-3d": ("Work", "Tasks"),
    "/autonomous-compliance": ("Risk & compliance", "Compliance"),
    "/approvals": ("Work", "Approvals"),
    "/agent-control-plane": ("Rules & safety", "Agent controls"),
    "/privacy": ("Privacy", "Overview"),
    "/privacy/data-discovery": ("Privacy", "Find personal data"),
    "/privacy/regulatory-intelligence": ("Privacy", "Law research"),
    "/privacy/rights-orchestration": ("Privacy", "Requests"),
    "/privacy/rights-consumer-delivery": ("Privacy", "Requests"),
    "/privacy/notice-governance": ("Privacy", "Notices"),
    "/consent": ("Privacy", "Consent"),
    "/consent/publishing": ("Privacy", "Consent"),
    "/consent/experiments": ("Privacy", "Consent"),
    "/consent/delivery": ("Privacy", "Consent"),
    "/consent/public-clients": ("Privacy", "Consent"),
    "/consent/native": ("Privacy", "Consent"),
    "/consent/profile-data": ("Privacy", "Consent"),
    "/consent/custom-indexes": ("Privacy", "Consent"),
    "/consent/bulk-jobs": ("Privacy", "Consent"),
    "/consent/publish-settings": ("Privacy", "Consent"),
    "/consent/global-opt-out": ("Privacy", "Consent"),
    "/consent/application-scans": ("Privacy", "Consent"),
    "/consent/scan-inventory": ("Privacy", "Consent"),
    "/consent/scan-notice-proposals": ("Privacy", "Consent"),
    "/consent/trust-center-authority": ("Privacy", "Consent"),
    "/data-use": ("Privacy", "Data use rules"),
    "/data-use/providers": ("Privacy", "Data use rules"),
    "/governance-agents": ("Risk & compliance", "AI risk"),
    "/governance/inventory": ("Risk & compliance", "AI risk"),
    "/ai-evidence-analysis": ("Risk & compliance", "Assessments"),
    "/assess/evidence-autopopulation": ("Risk & compliance", "Assessments"),
    "/ai-entity-tasks": ("Risk & compliance", "AI risk"),
    "/privacy/drop": ("Privacy", "Requests"),
    "/security": ("Risk & compliance", "Security"),
    "/third-party/vendor-onboarding": ("Risk & compliance", "Vendors"),
    "/third-party/contracts": ("Risk & compliance", "Vendors"),
    "/third-party/executive-reports": ("Risk & compliance", "Vendors"),
    "/third-party/intelligence": ("Risk & compliance", "Vendors"),
    "/third-party/lifecycle": ("Risk & compliance", "Vendors"),
    "/third-party/collaboration": ("Risk & compliance", "Vendors"),
    "/security/threats": ("Risk & compliance", "Security"),
    "/security/soc": ("Risk & compliance", "Security"),
    "/security/report": ("Risk & compliance", "Security"),
    "/security/assurance": ("Risk & compliance", "AI risk"),
    "/security/governance": ("Risk & compliance", "AI risk"),
    "/finance": ("Risk & compliance", "Financial controls"),
    "/partner": ("Settings", "Partner fleet"),
    "/permissions": ("Rules & safety", "What Second Shift can do"),
    "/simulate": ("Rules & safety", "Test a rule"),
    "/redact": ("Rules & safety", "Redaction check"),
    "/safety": ("Rules & safety", "Screening"),
    "/assessments": ("Risk & compliance", "Assessments"),
    "/compliance": ("Risk & compliance", "Compliance"),
    "/compliance/grc-studio": ("Risk & compliance", "Compliance"),
    "/compliance/policy-links": ("Risk & compliance", "Compliance"),
    "/compliance/scoping": ("Risk & compliance", "Compliance"),
    "/compliance/scope-actions": ("Risk & compliance", "Compliance"),
    "/compliance/scope-actions/mapping": ("Risk & compliance", "Compliance"),
    "/compliance/continuous-evidence": ("Risk & compliance", "Compliance"),
    "/compliance/obligations": ("Rules & safety", "Regulations and rules"),
    "/compartments": ("Rules & safety", "What Second Shift can do"),
    "/audit": ("Evidence & audit", "Activity log"),
    "/audit/receipts": ("Evidence & audit", "Trust receipts"),
    "/immune": ("Rules & safety", "Safety monitoring"),
    "/audit/evolution-ledger": ("Evidence & audit", "Learning history"),
    "/replay": ("Evidence & audit", "Task replay"),
    "/trust": ("Rules & safety", "Outside agents"),
    "/external-agents": ("Rules & safety", "Outside agents"),
    "/factory": ("Agents", "Build an agent"),
    "/models": ("Rules & safety", "Models"),
    "/my-agents": ("Rules & safety", "Outside agents"),
    "/skills": ("Agents", "Skills"),
    "/store": ("Agents", "Skills"),
    "/templates": ("Ask", "Start from a template"),
    "/tools": ("Agents", "Tools"),
    "/connections": ("Settings", "Connections"),
    "/plugins": ("Agents", "Tools"),
    "/styles": ("Agents", "Response styles"),
    "/mcp": ("Agents", "Tools"),
    "/channels": ("Settings", "Chat apps"),
    "/administration/document-vault": ("Evidence & audit", "Document vault"),
    "/workspace/recovery": ("Settings", "Backup & recovery"),
    "/settings": ("Settings", "General"),
    "/companion/admin": ("Settings", "People & roles"),
    "/users": ("Settings", "People & roles"),
    "/settings/sessions": ("Account", "Sessions"),
    "/spending-limits": ("Costs & value", "Spending limits"),
    "/tenants": ("Settings", "Workspaces"),
    "/workspace/tenant": ("Settings", "Workspaces"),
    "/cache": ("Settings", "Advanced"),
    "/embed-demo": ("Settings", "Advanced"),
    "/help": ("Help", "Help & diagnostics"),
    "/notifications": ("Account", "Notifications"),
    "/my-work": ("Work", "Tasks"),
    "/conversations": ("Ask", "Conversations"),
    "/human-conversations": ("Ask", "Conversations"),
    "/get-started/employee": ("Home", "Home"),
    "/project-workspaces": ("Work", "Projects"),
    "/devices": ("Account", "Devices"),
    "/access-requests": ("Account", "Permission requests"),
    "/budget": ("Costs & value", "Budget"),
    "/cost-reconciliation": ("Costs & value", "Compare cost records"),
    "/provider-spending": ("Costs & value", "Provider spending"),
}
_PAGES_BY_PATH = {p["path"]: p for p in PAGES}

# What people see for each registry group. The short keys stay stable because
# they also key each browser's remembered open/closed sidebar sections.
GROUP_TITLES: dict[str, str] = {
    "Operate": "Work",
    "Observe": "Insights",
    "Govern": "Governance",
    "Admin": "Administration",
    "Extend": "Library",
}


def group_title(group: str) -> str:
    """The sidebar, finder and Settings title for a registry group."""
    return GROUP_TITLES.get(group, group)

# What the page finder (Ctrl+K) matches beyond a page's label. HEADINGS holds
# a page's own heading where it differs from the label, so typing the words a
# person reads on the page finds it. SYNONYMS holds the plain words people
# type for a job ("approve" -> Approvals). The finder ranks an exact label,
# then an exact heading, then an exact synonym first (see
# static/second-shift-navfinder.js). Neither ever changes who can see a page.
HEADINGS: dict[str, str] = {
    "/legal": "Your digital legal team",
    "/budget": "Your budget before work starts",
    "/companion": "Your companion",
    "/companion/admin": "Companion policies",
}
SYNONYMS: dict[str, tuple[str, ...]] = {
    "/legal": ("counsel", "contracts", "paralegals", "associates", "legal matters"),
    "/approvals": ("approve", "approval", "decision", "decisions", "decide", "sign-off", "sign off"),
    # Agent controls holds the emergency stop and resume controls, and every
    # role that can find it can open it.
    "/agent-control-plane": ("pause", "stop", "emergency stop", "halt", "stop all work", "resume work"),
    "/billing": ("invoice", "invoices", "bill", "bills"),
    "/spend": ("cost", "costs", "spending"),
    "/help": ("help", "docs", "documentation", "support"),
    # The Activity log is also where activity is downloaded for auditors.
    "/audit": ("audit log", "history", "export"),
    "/privacy/rights-orchestration": (
        "dsar", "data subject request", "data subject access request", "rights request",
    ),
    "/users": ("invite", "people", "colleague", "colleagues", "add user", "members", "team members"),
    "/notifications": ("notification", "notifications", "alerts"),
    # Security & GRC keeps the incident register; Privacy keeps breaches.
    "/security": ("incident", "incidents", "security incident"),
    "/privacy": ("breach", "data breach"),
    # The sidebar's "New task" button opens Chat.
    "/chat": ("new task", "start a task", "new chat", "ask"),
    "/get-started/employee": ("get started", "first task"),
    "/conversations": ("chats", "chat history", "past chats"),
    "/access-requests": ("request access", "ask for permission"),
    "/shoring": ("hand a team's work", "hand over a team's work"),
}


# The job-named navigation ("areas" mode, ``[dashboard] navigation``): each
# area's title (also its sidebar entry), its hub page, and its sections in
# order. A page's area and section come from PAGE_AREAS. Ask is the Ask
# button; Account and Help are the account and help menus, not sidebar areas.
AREAS: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
_AREA_BY_TITLE = {title: (hub, sections) for title, hub, sections in AREAS}


# Areas reached from the top bar's menus rather than the sidebar.
_TOP_BAR_AREAS = frozenset({"Account", "Help"})


def parent_candidates(path: str) -> tuple[str, ...]:
    """Sidebar pages a page kept out of the sidebar (``in_nav: False``) sits
    under, best first: sidebar pages of its own area section, its area's hub,
    other sidebar pages of its area, then of its sidebar group. Empty for a
    page that is itself in the sidebar or unregistered."""
    page = _PAGES_BY_PATH.get(path)
    if page is None or page.get("in_nav", True):
        return ()
    shown = [p for p in PAGES if p.get("in_nav", True) and p["path"] != path]
    spot = PAGE_AREAS.get(path)
    found: list[str] = []
    if spot is not None:
        found += [p["path"] for p in shown if PAGE_AREAS.get(p["path"]) == spot]
        hub = _AREA_BY_TITLE.get(spot[0], ("",))[0]
        found += [hub] if any(p["path"] == hub for p in shown) else []
        found += [p["path"] for p in shown if PAGE_AREAS.get(p["path"], ("",))[0] == spot[0]]
    found += [p["path"] for p in shown if p["group"] == page["group"]]
    return tuple(dict.fromkeys(found))


def where(path: str, groups: list[dict], finder: list[dict]) -> dict | None:
    """Where a page kept out of the sidebar sits, for the sidebar highlight and
    the breadcrumb: its first parent this person's sidebar shows, and the page
    itself, each as ``{href, label}``. None for a sidebar page."""
    page = page_for(path)
    if page is None:
        return None
    visible = {link["href"]: link for group in groups for link in group["links"]}
    pages = {link["href"]: link for group in finder for link in group["links"]}
    here = pages.get(page["path"])
    spot = PAGE_AREAS.get(page["path"])
    if spot is not None and spot[0] in _TOP_BAR_AREAS:
        # Account and Help pages sit under their menu in the top bar, not the
        # sidebar: the breadcrumb leads to the area's own first page.
        hub = _AREA_BY_TITLE[spot[0]][0]
        parent, in_sidebar = (pages.get(hub) if hub != page["path"] else None), False
    else:
        parent = next((visible[href] for href in parent_candidates(page["path"]) if href in visible), None)
        in_sidebar = True
    if parent is None or here is None:
        return None
    return {"parent": {"href": parent["href"], "label": parent["label"]}, "sidebar": in_sidebar,
            "page": {"href": here["href"], "label": here["label"]}, "exact": path == page["path"]}


# Lockout guard: the pages an admin needs to *undo* a bad matrix save. Always
# visible + reachable for the admin role, no matter what the store says.
LOCKED = frozenset({("/settings", "admin"), ("/users", "admin")})


def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-ui-visibility.json"


def overrides() -> dict[str, dict[str, bool]]:
    """Validated ``{path: {role: bool}}`` admin overrides (diffs from default).

    Re-validated on read so a hand-edited / corrupt store can't inject an
    unknown page, an unknown role, or a non-bool value.
    """
    from maverick.record_documents import at

    try:
        text = at(store_path()).read_text()
        if text is None:
            return {}
        data = json.loads(text)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict[str, bool]] = {}
    for path, cells in data.items():
        if path not in _PAGES_BY_PATH or not isinstance(cells, dict):
            continue
        clean = {role: v for role, v in cells.items() if rbac.is_known_role(role) and isinstance(v, bool)}
        if clean:
            out[path] = clean
    return out


def _permission(page: dict, kind: str) -> str:
    # Self-service opens only the page shell. Native APIs still enforce own
    # account, approved fixed scopes and admin-only application management.
    return page[kind]


def eligible(page: dict, role: str) -> bool:
    """Whether ``role``'s permissions reach the page's security floor at all."""
    return _permission(page, "floor") in rbac.permissions_for(role)


def default_visible(page: dict, role: str) -> bool:
    """The page's out-of-the-box visibility for ``role`` (no overrides)."""
    return _permission(page, "default") in rbac.permissions_for(role)


def is_visible(page: dict, role: str | None) -> bool:
    """Whether ``role`` sees (and may load) ``page``.

    ``None`` = auth off = single-user local mode: always visible. Otherwise:
    locked pages are always visible to their locked role; a role that lacks
    the floor permission never sees the page; else the admin override wins,
    falling back to the default.
    """
    if role is None:
        return True
    if (page["path"], role) in LOCKED:
        return True
    if not eligible(page, role):
        return False
    cell = overrides().get(page["path"], {}).get(role)
    if cell is not None:
        return cell
    return default_visible(page, role)


def page_for(path: str) -> dict | None:
    """The registry page governing ``path`` (exact or longest segment-prefix
    match, so ``/goals/3/plan`` follows ``/goals``), or None if unregistered."""
    best = None
    for p in PAGES:
        root = p["path"]
        if path == root or path.startswith(root + "/"):
            if best is None or len(root) > len(best["path"]):
                best = p
    return best


def customer_ready(page: dict) -> bool:
    """False for a registered page marked ``ready: False``: governed and
    reachable by URL, but offered on no customer surface (sidebar, finder,
    Settings matrix)."""
    return page.get("ready", True) is not False


def nav_groups(
    role: str | None, *, scope_roles: dict[str, str | None] | None = None,
) -> list[dict]:
    """The sidebar nav for ``role``: ``[{label, links: [{href, label, icon}]}]``.

    Pages the role doesn't see are dropped; a group with nothing left is
    dropped whole. ``role=None`` (auth off) returns the full nav. Pages marked
    ``in_nav: False`` stay governed but never render a sidebar entry.
    """
    return _grouped_links(role, include_folded=False, scope_roles=scope_roles)


def finder_pages(
    role: str | None, *, scope_roles: dict[str, str | None] | None = None,
) -> list[dict]:
    """The page finder's index for ``role``, shaped exactly like ``nav_groups``.

    Same RBAC / lockout / admin-override resolution as the sidebar, but
    ``in_nav`` is ignored: pages folded out of the rail (reached in-page or by
    URL) are still destinations the role may open, so they must be searchable.
    """
    return _grouped_links(role, include_folded=True, scope_roles=scope_roles)


def navigation(
    role: str | None, *, scope_roles: dict[str, str | None] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Build the sidebar and finder from the same current visibility rules."""
    finder = finder_pages(role, scope_roles=scope_roles)
    groups = []
    for group in finder:
        links = [link for link in group["links"] if _PAGES_BY_PATH[link["href"]].get("in_nav", True)]
        if links:
            groups.append({**group, "links": links})
    return groups, finder


def _grouped_links(
    role: str | None, *, include_folded: bool,
    scope_roles: dict[str, str | None] | None = None,
) -> list[dict]:
    ov = overrides() if role is not None or scope_roles else {}
    groups: list[dict] = []
    permissions = {item: rbac.permissions_for(item)
                   for item in {role, *(scope_roles or {}).values()} if item is not None}
    # Groups follow the sidebar's order; a group reached only through folded
    # pages follows them, so the finder never reorders the sidebar's groups.
    sidebar_order: dict[str, int] = {}
    for page in PAGES:
        if not customer_ready(page):
            continue
        if not include_folded and not page.get("in_nav", True):
            continue
        page_role = (scope_roles or {}).get(page.get("scope", "workspace"), role)
        if page_role is not None:
            if (page["path"], page_role) not in LOCKED:
                allowed = permissions[page_role]
                if _permission(page, "floor") not in allowed:
                    continue
                cell = ov.get(page["path"], {}).get(page_role)
                shown = cell if cell is not None else _permission(page, "default") in allowed
                if not shown:
                    continue
        # Merge by group label (first-seen order), not adjacency: a page whose
        # group differs from its list neighbours (e.g. an entry re-homed to
        # Admin) must join its group, not split it into a duplicate section.
        if page.get("in_nav", True):
            sidebar_order.setdefault(page["group"], len(sidebar_order))
        for g in groups:
            if g["label"] == page["group"]:
                break
        else:
            g = {"label": page["group"], "title": group_title(page["group"]), "links": []}
            groups.append(g)
        g["links"].append(
            {
                "href": page["path"],
                "label": page["label"],
                "icon": page["icon"],
                "aliases": page.get("aliases", ""),
                "heading": HEADINGS.get(page["path"], ""),
                "synonyms": SYNONYMS.get(page["path"], ()),
            }
        )
    # Technical setup and diagnostics stay discoverable after everyday work.
    return sorted(groups, key=lambda group: (group["label"] == "Advanced tools",
                                             sidebar_order.get(group["label"], len(sidebar_order))))


__all__ = [
    "PAGES",
    "GROUP_TITLES",
    "LOCKED",
    "store_path",
    "overrides",
    "eligible",
    "default_visible",
    "is_visible",
    "page_for",
    "group_title",
    "nav_groups",
    "finder_pages",
    "HEADINGS",
    "SYNONYMS",
]
