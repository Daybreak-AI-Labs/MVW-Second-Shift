"""Dashboard RBAC: admin-managed user roles (admin / governance_lead / operator / approver /
responder / auditor / viewer).

This is the dashboard's *access-control* layer and is deliberately distinct from
the kernel's ``[roles]`` (``maverick.capability``), which only ATTENUATES an
agent's tool scope. Here a role GRANTS UI/API privilege, so it must never be
conflated with the kernel's attenuating roles.

Safety invariants (see maverick_dashboard.auth):
  * Meaningful only when an auth mode is on (OIDC / reverse-proxy / session).
    In no-token local mode ``caller_principal`` is None and every gate is a
    no-op — the local operator stays omnipotent, exactly as before.
  * A config-pinned bootstrap admin (``MAVERICK_DASHBOARD_ADMINS`` /
    ``[dashboard] admins``) is ALWAYS admin and is not stored here, so a wiped
    or tampered store can never lock every admin out.
  * The roster is control-plane data: one GLOBAL file, never per-tenant.

Store: ``~/.maverick/dashboard-users.json`` (0600), ``{principal: role}``, kept with
the other records (``maverick.record_documents``).
Once any role is written, a private sibling marker
(``dashboard-users.json.present``) records that a roster exists. A missing
roster is then a refusal (:class:`RosterMissingError`), never a silent return
to the authenticated-user default. A configured bootstrap admin keeps access
and can restore the file from backup or explicitly start a new, empty roster
(:func:`reset_missing_rosters`).

The marker is written AFTER the roster, never before: a first roster write
that fails (disk full, a sharing violation) must leave nothing behind, or every
retry would find a marker with no roster and be refused. A roster without a
marker is the state older installations are already in; the next read records
it (:func:`_backfill_record`).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Built-in roles, ordered most-privileged first (SCIM group resolution and the
# admin UIs rely on the order). Custom roles extend -- never replace -- these:
# the builtins are immutable, and every permission a custom role can hold is
# one of the atoms below, the same ones the require_permission call sites gate on.
ROLES = ("admin", "governance_lead", "operator", "approver", "responder", "auditor", "viewer")

# The permission atoms a role may grant. "view" is mandatory for every role:
# a principal who cannot even view has no working dashboard, which reads as
# breakage rather than policy.
PERMISSION_ATOMS = ("admin", "audit", "operate", "approve", "respond", "view")

# What comes with another permission. "operate" covered deciding approvals and
# stopping agents before those were permissions of their own, so a role that
# holds it holds both: built-in or custom, whenever it was stored. The rule is
# applied in permissions_for() and nowhere else.
IMPLIED_PERMISSIONS: dict[str, frozenset[str]] = {"operate": frozenset({"approve", "respond"})}


class RbacStoreError(RuntimeError):
    """RBAC policy exists but cannot be trusted.

    Treating a damaged roster as empty restores the authenticated-user default
    and can promote a deliberately-demoted viewer back to operator. Readers and
    mutators therefore refuse present-but-invalid state instead of overwriting
    or broadening it.
    """


class RosterRollbackError(RbacStoreError):
    """A role change was refused by the activity log and putting the role list
    back failed, so the list may now hold the change."""


class RosterMissingError(RbacStoreError):
    """A role list was recorded on this installation, but the roster file is gone.

    Deleting, failing to restore, or misresolving the roster must not return
    every demoted person to the default role.
    """


# What the person who runs Second Shift can do, in the words the sign-in page, the
# Users page and the API refusal all share. An installation set up with the
# local owner has no administrator in configuration, and the owner's admin role
# lived only in the lost list, so the file-level step is part of the guidance.
ROSTER_RECOVERY = (
    "Restore the role list from a backup. Or have an administrator set up in configuration "
    "start a new, empty role list on the Users page. If none is set up, add the owner's email "
    "as user:name@company.com to [dashboard] admins in config.toml, or set "
    "MAVERICK_DASHBOARD_ADMINS, then restart Second Shift and sign in to start a new list."
)

# Permission lattice. The "audit" permission gates the audit-trail read surface
# (/api/v1/audit/*): the who-did-what-when record that can name principals, tool
# inputs and costs. It is held by "admin" and by the dedicated read-only
# "auditor" role -- separation of duties, so a compliance reviewer can read the
# audit log WITHOUT also holding operate/admin (run goals, change settings,
# manage users). "auditor" deliberately grants NOTHING operational: audit + view
# only. "operator"/"viewer" do NOT get "audit" -- reading the trail is a
# distinct grant, not implied by operate. "governance_lead" is the one
# deliberate combination: a day-to-day operator who also reads the trail
# (operate + audit + view), with no administrator rights.
# "approve" (decide a request waiting for a person) and "respond" (suspend,
# resume and limit agents, the emergency stop where an operator may use it,
# and acknowledging or re-checking drift) are the two parts of "operate"
# that can be given on their own: "approver" and "responder" hold one each
# and nothing else but view. Every role that holds "operate" holds both
# (IMPLIED_PERMISSIONS).
_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"admin", "audit", "operate", "approve", "respond", "view"}),  # users, settings, secrets, + all
    "governance_lead": frozenset({"audit", "operate", "approve", "respond", "view"}),  # operator who also reads the audit trail
    "operator": frozenset({"operate", "approve", "respond", "view"}),  # run/cancel goals, approve, tools
    "approver": frozenset({"approve", "view"}),                 # decide requests waiting for a person
    "responder": frozenset({"respond", "view"}),                # suspend, resume and limit agents
    "auditor": frozenset({"audit", "view"}),                    # read audit trail (read-only)
    "viewer": frozenset({"view"}),                              # read-only
}


def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-users.json"


def default_role() -> str:
    """Role for an authenticated user with no explicit assignment. Defaults to
    ``viewer``; grant operate or admin explicitly, or configure a different
    first-login role in ``[dashboard] default_role``."""
    try:
        from maverick.config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            raise RbacStoreError("RBAC defaults unavailable: an active config source is invalid")
        dashboard = cfg.get("dashboard", {})
        if dashboard is None:
            dashboard = {}
        if not isinstance(dashboard, dict):
            raise RbacStoreError("RBAC defaults invalid: [dashboard] must be a table")
        if "default_role" not in dashboard:
            return "viewer"
        r = dashboard.get("default_role")
        if isinstance(r, str) and is_known_role(r):
            return r
        raise RbacStoreError("RBAC default_role is invalid")
    except RbacStoreError:
        raise
    except Exception as exc:
        raise RbacStoreError(f"RBAC defaults unavailable: {exc}") from exc
def permissions_for(role: str | None) -> frozenset[str]:
    """The permissions ``role`` holds, with any that come with one of them
    (:data:`IMPLIED_PERMISSIONS`). Every gate asks here, so nothing can hold
    ``operate`` without ``approve`` and ``respond``. A role that is unknown,
    or whose record cannot be read, holds none, so it gains none."""
    held = _stored_permissions(role)
    return held.union(*(IMPLIED_PERMISSIONS[atom] for atom in held if atom in IMPLIED_PERMISSIONS))


def _stored_permissions(role: str | None) -> frozenset[str]:
    name = role or ""
    builtin = _PERMISSIONS.get(name)
    if builtin is not None:
        return builtin
    if not name:
        return frozenset()
    try:
        rec = _load_custom().get(name)
    except RbacStoreError:
        # A corrupt custom-role store must DENY, not crash every request or --
        # worse -- broaden access through some fallback.
        from . import strict_reads

        if strict_reads.active():
            raise
        return frozenset()
    if rec is None:
        return frozenset()
    return frozenset(rec["permissions"])


_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")


def custom_roles_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-custom-roles.json"


def _validate_custom_role(name: object, rec: object) -> tuple[str, dict]:
    if not isinstance(name, str) or not _ROLE_NAME.match(name):
        raise RbacStoreError(f"custom role store corrupt: invalid role name {name!r}")
    if name in ROLES:
        raise RbacStoreError(f"custom role store corrupt: {name!r} shadows a built-in role")
    if not isinstance(rec, dict):
        raise RbacStoreError(f"custom role store corrupt: record for {name!r} must be an object")
    perms = rec.get("permissions")
    if (
        not isinstance(perms, list)
        or not perms
        or any(p not in PERMISSION_ATOMS for p in perms)
        or len(set(perms)) != len(perms)
    ):
        raise RbacStoreError(f"custom role store corrupt: invalid permissions for {name!r}")
    if "view" not in perms:
        raise RbacStoreError(f"custom role store corrupt: {name!r} must grant view")
    description = rec.get("description", "")
    if not isinstance(description, str) or len(description) > 200:
        raise RbacStoreError(f"custom role store corrupt: invalid description for {name!r}")
    ordered = [p for p in PERMISSION_ATOMS if p in perms]
    return name, {"permissions": ordered, "description": description}


def _read_store_text(p: Path) -> str | None:
    """Read one current record, with private-file checks in file deployments."""
    from maverick import record_documents

    doc = record_documents.at(p)
    if record_documents.using_postgres():
        return doc.read_text()
    from maverick.file_lock import ensure_private_directory, ensure_private_file
    from maverick.paths import maverick_home

    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not doc.exists():
        return None
    ensure_private_file(p)
    text = doc.read_text()
    if text is None:
        raise FileNotFoundError("the saved record is missing")
    return text


def _load_custom() -> dict[str, dict]:
    p = custom_roles_path()
    raw = _read_store_text(p)
    if raw is None:
        return {}
    try:
        data = _decode_json_object(raw, label="custom role store")
    except RbacStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise RbacStoreError(f"custom role store unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise RbacStoreError("custom role store corrupt: top-level value must be an object")
    out: dict[str, dict] = {}
    for raw_name, raw_rec in data.items():
        name, rec = _validate_custom_role(raw_name, raw_rec)
        out[name] = rec
    return out


def is_known_role(role: object) -> bool:
    if not isinstance(role, str):
        return False
    if role in ROLES:
        return True
    try:
        return role in _load_custom()
    except RbacStoreError:
        return False


def _presence_marker(path: Path) -> Path:
    """Private sibling recording that this roster has existed."""
    return path.with_name(path.name + ".present")


def _roster_recorded(path: Path) -> bool:
    from maverick import record_documents

    if record_documents.using_postgres():
        try:
            return record_documents.at(_presence_marker(path)).exists()
        except OSError as exc:
            raise RbacStoreError(f"RBAC roster state unreadable: {exc}") from exc
    try:
        _presence_marker(path).lstat()  # a dangling or odd entry still counts
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RbacStoreError(f"RBAC roster state unreadable: {exc}") from exc
    return True


def _record_roster(path: Path) -> None:
    """Durably note that ``path`` holds assigned roles (idempotent)."""
    from maverick import record_documents

    if not _roster_recorded(path):
        record_documents.at(_presence_marker(path)).write_text(
            json.dumps({"schema": 1, "roster": path.name}, sort_keys=True))


def _missing_roster(path: Path, label: str) -> dict:
    if _roster_recorded(path):
        raise RosterMissingError(
            f"{label} is missing although this installation recorded one. {ROSTER_RECOVERY}"
        )
    return {}


def _backfill_record(path: Path) -> None:
    # Installations whose roster predates the marker gain it on first read.
    try:
        _record_roster(path)
    except (OSError, RbacStoreError) as exc:
        import logging

        logging.getLogger(__name__).warning("RBAC roster marker not recorded: %s", exc)


def _load() -> dict[str, str]:
    from maverick import record_documents

    p = store_path()
    marked = False
    try:
        if record_documents.using_postgres():
            raw, marker = record_documents.read_texts(p, _presence_marker(p))
            marked = marker is not None
            if raw is None:
                if marked:
                    raise RosterMissingError(
                        f"The role list is missing although this installation recorded one. {ROSTER_RECOVERY}")
                return {}
        else:
            raw = _read_store_text(p)
            if raw is None:
                return _missing_roster(p, "The role list")
        data = _decode_json_object(raw, label="RBAC roster")
    except RbacStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise RbacStoreError(f"RBAC roster unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise RbacStoreError("RBAC roster corrupt: top-level value must be an object")
    out: dict[str, str] = {}
    for principal, role in data.items():
        if not isinstance(principal, str) or not principal.strip() or principal != principal.strip():
            raise RbacStoreError("RBAC roster corrupt: principals must be non-blank trimmed strings")
        if not is_known_role(role):
            raise RbacStoreError(f"RBAC roster corrupt: invalid role for {principal!r}")
        out[principal] = role
    if not marked:
        _backfill_record(p)
    return out


def _decode_json_object(raw: str, *, label: str) -> object:
    def _reject_constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object)
    except (TypeError, ValueError) as exc:
        raise RbacStoreError(f"{label} corrupt: {exc}") from exc


def list_users() -> dict[str, str]:
    """All explicitly-assigned {principal: role} (bootstrap admins excluded)."""
    return _load()


def get_stored_role(principal: str) -> str | None:
    return _load().get((principal or "").strip())


def tenant_store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-tenant-roles.json"


def _load_tenant() -> dict[str, dict[str, str]]:
    p = tenant_store_path()
    raw = _read_store_text(p)
    if raw is None:
        return _missing_roster(p, "The workspace role list")
    try:
        data = _decode_json_object(raw, label="tenant RBAC roster")
    except RbacStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise RbacStoreError(f"tenant RBAC roster unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise RbacStoreError("tenant RBAC roster corrupt: top-level value must be an object")
    out: dict[str, dict[str, str]] = {}
    for tenant, members in data.items():
        if not isinstance(tenant, str) or not tenant.strip() or tenant != tenant.strip():
            raise RbacStoreError("tenant RBAC roster corrupt: tenant ids must be trimmed strings")
        if not isinstance(members, dict):
            raise RbacStoreError(f"tenant RBAC roster corrupt: members for {tenant!r} must be an object")
        clean: dict[str, str] = {}
        for principal, role in members.items():
            if not isinstance(principal, str) or not principal.strip() or principal != principal.strip():
                raise RbacStoreError(
                    f"tenant RBAC roster corrupt: invalid principal in {tenant!r}"
                )
            if not is_known_role(role):
                raise RbacStoreError(
                    f"tenant RBAC roster corrupt: invalid role for {principal!r}"
                )
            clean[principal] = role
        out[tenant] = clean
    _backfill_record(p)
    return out


def _tenant_removed(tenant: str) -> bool:
    from maverick.tenant.registry import tenant_retired

    if not (tenant or "").strip():
        return False
    try:
        return tenant_retired(tenant)
    except Exception as exc:
        raise RbacStoreError("workspace membership authority is unavailable") from exc


def tenant_role_scope_initialized() -> bool:
    """Whether workspace membership authority has ever been initialized.

    Keep the roster even when its last grant is revoked. A missing recorded
    roster raises rather than silently restoring installation-wide defaults.
    """
    from maverick import record_documents

    _load_tenant()
    return record_documents.at(tenant_store_path()).exists()


def get_tenant_role(tenant: str, principal: str) -> str | None:
    """The principal's role within ``tenant``, or None if no membership."""
    if _tenant_removed(tenant):
        return None
    members = _load_tenant().get((tenant or "").strip(), {})
    return members.get((principal or "").strip())


__all__ = [
    "ROLES",
    "PERMISSION_ATOMS",
    "IMPLIED_PERMISSIONS",
    "ROSTER_RECOVERY",
    "RbacStoreError",
    "RosterMissingError",
    "store_path",
    "default_role",
    "permissions_for",
    "list_users",
    "get_stored_role",
    "tenant_store_path",
    "get_tenant_role",
    "custom_roles_path",
    "is_known_role",
]
