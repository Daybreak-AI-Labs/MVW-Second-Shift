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
import math
from dataclasses import dataclass, field

from ..file_lock import atomic_read_text
from ..paths import _tenant_namespace_key, canonical_tenant_id, maverick_home

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

# Upper bound on each per-tenant feature-override list. A control-plane roster
# edited by an operator should never carry an unbounded blob; a plan has only a
# handful of features and the catalog a few dozen, so 200 is generous headroom
# while keeping the record small.
MAX_FEATURE_OVERRIDES = 200


class TenantRegistryError(RuntimeError):
    """Tenant control-plane state exists but cannot be trusted."""


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


__all__ = [
    "ACTIVE",
    "SUSPENDED",
    "MAX_FEATURE_OVERRIDES",
    "TenantRecord",
    "BILLING_CURRENT",
    "BILLING_PAST_DUE",
    "TenantRegistryError",
    "tenant_retired",
]
