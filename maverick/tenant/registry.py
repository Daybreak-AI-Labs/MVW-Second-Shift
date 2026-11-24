"""Tenant lifecycle / provisioning registry — the hosted control plane's roster.

A :class:`Workspace` isolates one tenant's *data*; this registry is the
*operator's* record of which tenants exist, their status (active / suspended),
plan, and per-tenant quota. It lives at the **un-namespaced** root
(``<home>/tenant_registry.json``, ``tenant=None``) because it is cross-tenant
control-plane state, not any one tenant's data.

Lifecycle: ``create`` → ``suspend`` / ``resume`` → ``delete`` (optionally
purging the tenant's data dir). :func:`assert_tenant_active` is the enforcement
hook a request path calls before doing work for a tenant, so a suspended tenant
is refused. Identifiers are never recycled: namespace reservations and
deletion history outlive the roster and optional data purge. Before any
registry or deletion history exists, single-tenant and unprovisioned deployments
retain their existing behavior.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import time
from dataclasses import dataclass, field

from ..file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from ..paths import _tenant_namespace_key, bind_tenant_namespace, canonical_tenant_id, maverick_home

log = logging.getLogger(__name__)

ACTIVE = "active"
SUSPENDED = "suspended"
_STATUSES = frozenset({ACTIVE, SUSPENDED})

# Billing (payment) status, distinct from the lifecycle ``status`` above: this
# tracks whether the tenant's Stripe subscription/invoices are being paid. It is
# flipped by :mod:`maverick.billing_stripe`'s webhook handler and consulted by
# :func:`maverick.billing.tenant_entitled` -- a ``past_due`` tenant is served the
# base ("free") entitlement tier without losing its subscribed ``plan`` (so a
# ``payment_succeeded`` webhook can restore it). ``current`` is the default and
# the state of every tenant provisioned before Stripe billing exists.
BILLING_CURRENT = "current"
BILLING_PAST_DUE = "past_due"
_BILLING_STATUSES = frozenset({BILLING_CURRENT, BILLING_PAST_DUE})

# A newly provisioned tenant has no daily spend cap unless one is chosen
# (``0`` means no cap). Administrators set workspace and per-person limits in
# Admin > Spending limits (maverick.spending_limits) or a daily cap here.
DEFAULT_TENANT_DAILY_DOLLARS = 0.0

# Upper bound on each per-tenant feature-override list. A control-plane roster
# edited by an operator should never carry an unbounded blob; a plan has only a
# handful of features and the catalog a few dozen, so 200 is generous headroom
# while keeping the record small.
MAX_FEATURE_OVERRIDES = 200

# Serializes the roster load-modify-save across threads in this process; the
# cross_process_lock below extends that across processes (the registry is edited
# from both the CLI and the dashboard, which are separate processes).
_REGISTRY_LOCK = threading.Lock()


class TenantRegistryError(RuntimeError):
    """Tenant control-plane state exists but cannot be trusted."""


def _registry_path():
    return maverick_home() / "tenant_registry.json"


def _retirement_path(tenant_id: str):
    key = _tenant_namespace_key(tenant_id)
    return maverick_home() / ".tenant-deletions" / (hashlib.sha256(key.encode("ascii")).hexdigest() + ".json")


def _retirement(tenant_id: str) -> dict | None:
    from ..file_lock import ensure_private_file
    path = _retirement_path(tenant_id)
    if not path.exists():
        return None
    try:
        ensure_private_file(path)
        value = _decode_json(atomic_read_text(path), label="tenant deletion tombstone")
        if (not isinstance(value, dict) or value.get("version") not in (1, 2)
                or not isinstance(value.get("id"), str)
                or _tenant_namespace_key(value["id"]) != _tenant_namespace_key(tenant_id)
                or value["id"] != canonical_tenant_id(value["id"])):
            raise ValueError("invalid deletion identity")
        when = value.get("deleted_at")
        if not isinstance(when, (int, float)) or not math.isfinite(when) or when < 0:
            raise ValueError("invalid deletion time")
        if value["version"] == 2:
            saved = TenantRecord.from_dict(value.get("record"))
            if (saved.id != value["id"] or value.get("state") not in ("removed", "restored")
                    or type(value.get("purged")) is not bool):
                raise ValueError("invalid deletion record")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise TenantRegistryError("Tenant deletion history is unavailable; provisioning and admission are refused.") from exc
    return value


def _retired(tenant_id: str) -> bool:
    value = _retirement(tenant_id)
    return value is not None and value.get("state", "removed") == "removed"


def tenant_retired(tenant_id: str) -> bool:
    """Public read gate for role stores outside the core package."""
    return _retired(_lookup_id(tenant_id))


@dataclass(frozen=True)
class TenantRecord:
    """One provisioned tenant."""

    id: str
    status: str = ACTIVE
    plan: str = "free"
    display_name: str = ""
    # Per-tenant aggregate spend cap (USD/day); 0 = unlimited (defer to global).
    max_daily_dollars: float = 0.0
    created_at: float = 0.0
    updated_at: float = 0.0
    # Stripe customer id for platform billing (maverick.billing_stripe), stored
    # once created so the customer is looked up, not re-created. Empty = the
    # tenant has never been synced to Stripe. Not a secret (a ``cus_...`` handle).
    stripe_customer_id: str = ""
    # Payment state (see BILLING_CURRENT / BILLING_PAST_DUE). Never a secret.
    billing_status: str = BILLING_CURRENT
    # Bring-your-own-key opt-in: when true (and the deployment enabled
    # [providers] per_tenant_keys), this tenant runs on its OWN provider API key,
    # resolved from the secret provider under a tenant-scoped name -- NOT stored
    # here. Just a flag; the key bytes never touch the registry. Off => the
    # tenant uses the deployment-global provider key (unchanged behavior).
    byok: bool = False
    # Per-tenant feature overrides layered ON TOP of the plan's entitlements:
    # ``{"add": [feature, ...], "remove": [feature, ...]}`` (empty ``{}`` when
    # unused). ``add`` grants features the plan lacks; ``remove`` revokes plan
    # features. Resolved by :func:`maverick.billing.effective_features`
    # (precedence: ``(plan | add) - remove``). Kept out of the serialized record
    # entirely when empty, so tenants that never override stay byte-identical.
    feature_overrides: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "id": self.id, "status": self.status, "plan": self.plan,
            "display_name": self.display_name,
            "max_daily_dollars": self.max_daily_dollars,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }
        # Only serialize the optional fields when they carry non-default state, so
        # a registry written before this feature stays byte-identical and the
        # on-disk file does not grow a column for tenants that never use it.
        if self.stripe_customer_id:
            out["stripe_customer_id"] = self.stripe_customer_id
        if self.billing_status != BILLING_CURRENT:
            out["billing_status"] = self.billing_status
        if self.byok:
            out["byok"] = self.byok
        if self.feature_overrides:
            out["feature_overrides"] = self.feature_overrides
        return out

    @classmethod
    def from_dict(cls, d: dict) -> TenantRecord:
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or not d["id"].strip():
            raise ValueError("tenant record must be an object with an id")
        tenant_id = d["id"]
        if tenant_id != tenant_id.strip():
            raise ValueError("tenant id must be trimmed")
        tenant_id = _validate_id(tenant_id)
        status = d.get("status", ACTIVE)
        if not isinstance(status, str):
            raise ValueError("tenant status must be a string")
        if status not in _STATUSES:
            raise ValueError(f"unknown tenant status: {status!r}")
        try:
            cap = float(d.get("max_daily_dollars", 0.0) or 0.0)
            created = float(d.get("created_at", 0.0) or 0.0)
            updated = float(d.get("updated_at", 0.0) or 0.0)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError("tenant numeric fields must be finite numbers") from exc
        if not all(math.isfinite(value) and value >= 0 for value in (cap, created, updated)):
            raise ValueError("tenant numeric fields must be finite and non-negative")
        plan = d.get("plan", "free") or "free"
        display_name = d.get("display_name", "") or ""
        if not isinstance(plan, str) or not isinstance(display_name, str):
            raise ValueError("tenant plan and display_name must be strings")
        stripe_customer_id = d.get("stripe_customer_id", "") or ""
        if not isinstance(stripe_customer_id, str):
            raise ValueError("tenant stripe_customer_id must be a string")
        billing_status = d.get("billing_status", BILLING_CURRENT) or BILLING_CURRENT
        if not isinstance(billing_status, str):
            raise ValueError("tenant billing_status must be a string")
        if billing_status not in _BILLING_STATUSES:
            raise ValueError(f"unknown tenant billing_status: {billing_status!r}")
        byok = d.get("byok", False)
        if not isinstance(byok, bool):
            raise ValueError("tenant byok must be a boolean")
        raw_overrides = d.get("feature_overrides", {})
        if raw_overrides in (None, ""):
            raw_overrides = {}
        if not isinstance(raw_overrides, dict):
            raise ValueError("tenant feature_overrides must be an object")
        unknown_keys = set(raw_overrides) - {"add", "remove"}
        if unknown_keys:
            raise ValueError(
                f"tenant feature_overrides has unknown keys: {sorted(unknown_keys)}"
            )
        feature_overrides = _normalize_feature_overrides(
            raw_overrides.get("add"), raw_overrides.get("remove")
        )
        return cls(
            id=tenant_id, status=status, plan=plan,
            display_name=display_name, max_daily_dollars=cap,
            created_at=created, updated_at=updated,
            stripe_customer_id=stripe_customer_id.strip(),
            billing_status=billing_status,
            byok=byok,
            feature_overrides=feature_overrides,
        )

    @property
    def active(self) -> bool:
        return self.status == ACTIVE


def _validate_id(tenant_id: str) -> str:
    tid = (tenant_id or "").strip()
    if not tid:
        raise ValueError("tenant id is required")
    # Persist one canonical Unicode spelling and enforce portable path rules.
    return canonical_tenant_id(tid)


def _lookup_id(tenant_id: str | None) -> str:
    tid = (tenant_id or "").strip()
    return canonical_tenant_id(tid) if tid else ""


def _clean_feature_list(value: object, *, side: str) -> list[str]:
    """Validate one override list (``add`` or ``remove``): strings only, no
    blanks, deduped, sorted, capped. Raises ``ValueError`` on bad input."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"feature_overrides {side!r} must be a list")
    if len(value) > MAX_FEATURE_OVERRIDES:
        raise ValueError(
            f"feature_overrides {side!r} exceeds the {MAX_FEATURE_OVERRIDES}-entry cap"
        )
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"feature_overrides {side!r} entries must be strings")
        name = item.strip()
        if not name:
            raise ValueError(f"feature_overrides {side!r} entries must be non-blank")
        if name not in seen:
            seen.add(name)
            out.append(name)
    out.sort()
    return out


def _normalize_feature_overrides(add: object, remove: object) -> dict[str, list[str]]:
    """Validate + normalize the per-tenant override lists into a canonical dict.

    Returns ``{}`` when both lists are empty (so a tenant that never uses the
    feature stays byte-identical on disk), else ``{"add": [...], "remove":
    [...]}`` with sorted, deduped entries. A feature in BOTH lists is rejected
    (rather than silently letting one win) so an operator's contradictory input
    is surfaced instead of guessed."""
    add_list = _clean_feature_list(add, side="add")
    remove_list = _clean_feature_list(remove, side="remove")
    overlap = sorted(set(add_list) & set(remove_list))
    if overlap:
        raise ValueError(
            "feature_overrides: a feature must not be in both add and remove: "
            + ", ".join(overlap)
        )
    if not add_list and not remove_list:
        return {}
    return {"add": add_list, "remove": remove_list}


def _load() -> dict[str, TenantRecord]:
    from ..file_lock import ensure_private_file

    ensure_private_directory(maverick_home())
    path = _registry_path()
    ensure_private_directory(path.parent)
    if not path.exists():
        return {}
    try:
        ensure_private_file(path)
        raw = _decode_json(atomic_read_text(path), label="tenant registry")
    except TenantRegistryError:
        raise
    except OSError as exc:
        raise TenantRegistryError(f"tenant registry unreadable: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("tenants"), list):
        raise TenantRegistryError(
            "tenant registry corrupt: top-level object must contain a tenants list"
        )
    out: dict[str, TenantRecord] = {}
    namespace_owners: dict[str, str] = {}
    for d in raw["tenants"]:
        try:
            rec = TenantRecord.from_dict(d)
        except (TypeError, ValueError) as exc:
            raise TenantRegistryError(f"tenant registry corrupt: {exc}") from exc
        if rec.id in out:
            raise TenantRegistryError(f"tenant registry corrupt: duplicate tenant {rec.id!r}")
        namespace_key = _tenant_namespace_key(rec.id)
        prior = namespace_owners.get(namespace_key)
        if prior is not None and prior != rec.id:
            raise TenantRegistryError(
                "tenant registry corrupt: tenant ids "
                f"{prior!r} and {rec.id!r} alias the same filesystem namespace"
            )
        namespace_owners[namespace_key] = rec.id
        out[rec.id] = rec
    return out


def _decode_json(raw: str, *, label: str) -> object:
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
        raise TenantRegistryError(f"{label} corrupt: {exc}") from exc


def _save(records: dict[str, TenantRecord]) -> None:
    payload = {"tenants": [records[k].to_dict() for k in sorted(records)]}
    # Atomic temp+replace (0600): a bare O_TRUNC write truncates in place, so a
    # concurrent _load()/is_active() reader sees a half-written file -> its
    # JSONDecodeError is swallowed as an EMPTY roster, which spuriously refuses a
    # legitimately-active tenant. Each mutator also holds _REGISTRY_LOCK +
    # cross_process_lock across the whole load-modify-save so two edits (e.g. a
    # suspend racing a set_quota) can't have the second save clobber the first.
    atomic_write_text(
        _registry_path(),
        json.dumps(payload, indent=2, sort_keys=True),
    )


def _locked(*, strict: bool = False):
    """Serialize a roster load-modify-save in-process AND cross-process.

    ``strict=True`` is used when a roster read participates in an admission
    transaction.  On a filesystem without a real process lock, admission must
    fail closed instead of racing a control-plane cap change.
    """
    from contextlib import ExitStack

    from ..authority_effects import authority_effect_fence

    ensure_private_directory(maverick_home())
    ensure_private_directory(_registry_path().parent)
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_REGISTRY_LOCK)
        stack.enter_context(cross_process_lock(_registry_path(), strict=strict))
        # Admission paths that already hold the roster (provider_admission)
        # must be able to repair the default tenant without re-locking: the
        # lock is not re-entrant and the flock would block the same process.
        _LOCK_STATE.held = True
        stack.callback(setattr, _LOCK_STATE, "held", False)
        return stack.pop_all()


_LOCK_STATE = threading.local()


def _roster_locked_by_this_thread() -> bool:
    return bool(getattr(_LOCK_STATE, "held", False))


#: Roster label for the tenant a deployment ran in before it had workspaces.
DEFAULT_WORKSPACE_DISPLAY_NAME = "Default workspace"


def _default_record(records: dict[str, TenantRecord]) -> TenantRecord | None:
    """A fresh active row for the implicit default tenant, or ``None`` when the
    deployment has no binding or the roster already lists it. Caller holds the
    registry lock."""
    from ..paths import implicit_tenant_id

    try:
        tid = _lookup_id(implicit_tenant_id())
    except Exception:
        return None
    if not tid or tid in records:
        return None
    namespace_key = _tenant_namespace_key(tid)
    if any(_tenant_namespace_key(existing) == namespace_key for existing in records):
        return None
    try:
        bind_tenant_namespace(tid)
        from ..workspace import Workspace
        ensure_private_directory(Workspace(tid).root)
    except Exception as exc:
        log.error("default tenant %r could not be provisioned: %s", tid, exc)
        return None
    now = time.time()
    return TenantRecord(
        id=tid, status=ACTIVE, plan="free",
        display_name=DEFAULT_WORKSPACE_DISPLAY_NAME,
        max_daily_dollars=DEFAULT_TENANT_DAILY_DOLLARS,
        created_at=now, updated_at=now,
    )


def _audit_default_registered(tenant_id: str, *, trigger: str, actor: str = "system") -> None:
    from ..audit import EventKind, audit_event

    audit_event(
        EventKind.TENANT_DEFAULT_REGISTERED, agent="system", _global=True,
        actor=actor, tenant=tenant_id, trigger=trigger,
    )


def ensure_default_tenant_registered(*, actor: str = "system") -> TenantRecord | None:
    """Repair an install whose roster predates the default-tenant rule.

    When a roster exists but lacks the deployment's implicit default tenant,
    add it as active and write an audit event. Returns the new record, or
    ``None`` when nothing needed doing (no roster, no binding, already
    listed, or paused on purpose). Safe to call on every startup or admission.
    """
    if not _registry_path().exists():
        return None

    def _register() -> TenantRecord | None:
        records = _load()
        default = _default_record(records)
        if default is not None:
            records[default.id] = default
            _save(records)
        return default

    if _roster_locked_by_this_thread():
        default = _register()
    else:
        with _locked():
            default = _register()
    if default is None:
        return None
    _audit_default_registered(default.id, trigger="repair", actor=actor)
    log.warning("tenant registry: registered the default workspace %r so it "
                "keeps running alongside the named workspaces", default.id)
    return default


def _is_implicit_default(tid: str) -> bool:
    from ..paths import implicit_tenant_id

    try:
        return bool(tid) and _lookup_id(implicit_tenant_id()) == tid
    except Exception:
        return False


def is_active(tenant_id: str | None) -> bool:
    """Whether a tenant may do work.

    The registry is opt-in: before any roster or deletion history exists, named tenants are
    accepted for single-tenant and unprovisioned deployments. Once a roster
    exists, only provisioned active tenants may do work; unknown tenant IDs
    include deleted tenants and are refused.
    """
    tid = _lookup_id(tenant_id)
    if not tid:
        return True
    try:
        if _retired(tid):
            return False
        rec = _load().get(tid)
    except TenantRegistryError:
        return False
    if rec is None:
        if not _registry_path().exists():
            return True
        if _is_implicit_default(tid):
            try:
                rec = ensure_default_tenant_registered()
            except Exception:
                return False
            return rec is not None and rec.active
        return False
    return rec.active


__all__ = [
    "ACTIVE",
    "SUSPENDED",
    "DEFAULT_TENANT_DAILY_DOLLARS",
    "MAX_FEATURE_OVERRIDES",
    "TenantRecord",
    "BILLING_CURRENT",
    "BILLING_PAST_DUE",
    "TenantRegistryError",
    "tenant_retired",
    "is_active",
]
