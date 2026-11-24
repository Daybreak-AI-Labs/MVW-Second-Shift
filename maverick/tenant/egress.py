"""Per-tenant egress policy plane.

:mod:`maverick.sandbox.network_policy` restricts egress **per tool**. This adds a
plane **per tenant** that applies to *every* tool a tenant's agents run, so one
tenant can't reach another tenant's resources or a cloud metadata endpoint
regardless of which tool makes the call. The two compose with **AND**: a host is
reachable only if it passes *both* the tenant plane and the per-tool policy.

Config:

    [egress]                       # default plane (all tenants without an override)
    deny  = ["169.254.169.254"]    # block cloud metadata (tenants without an override)
    allow = []                     # empty = allow-all (after deny)

    [tenancy.egress.acme]          # per-tenant override: REPLACES [egress], so
                                   # repeat any default deny it must keep
    allow = ["api.acme.com", "*.acme-internal.net"]
    deny  = ["*"]

Resolution: ``[tenancy.egress.<tenant>]`` if present, else ``[egress]``, else
empty (allow-all — unchanged default). An unreadable configuration source
denies every host instead. ``host_allowed`` is the pure decision
(deny wins; non-empty allow restricts), unit-tested in isolation.
"""
from __future__ import annotations

import ipaddress
import socket

from ..sandbox.network_policy import _matches


def _resolve_tenant(tenant: str | None) -> str | None:
    if tenant == "__active__":
        from ..paths import current_tenant_id
        return current_tenant_id()
    return tenant


#: The plane used when a configuration source cannot be read: the configured
#: deny and allow lists may have been lost, so nothing is reachable.
_UNREADABLE_CONFIG_PLANE = {"deny": ["*"]}


def load_tenant_egress(tenant: str | None = "__active__") -> dict:
    """The egress plane for ``tenant``: the per-tenant override or the default.

    ``load_config`` returns defaults for a malformed file; that must not turn a
    configured deny list into allow-all, so an unreadable source denies all.
    """
    try:
        from ..config import config_source_errors, load_config
        cfg = load_config() or {}
        if config_source_errors(include_tenant=True):
            return dict(_UNREADABLE_CONFIG_PLANE)
    except Exception:  # pragma: no cover -- config never blocks egress
        return {}
    tid = _resolve_tenant(tenant)
    if tid:
        per = ((cfg.get("tenancy", {}) or {}).get("egress", {}) or {}).get(tid)
        if isinstance(per, dict):
            return per
    default = cfg.get("egress", {}) or {}
    return default if isinstance(default, dict) else {}


def _canonical_ip(host: str) -> str:
    value = host.strip().lower().removesuffix(".")
    if value.startswith("[") and value.endswith("]"):
        # URL-style IPv6 literal: "[::ffff:a.b.c.d]" is the same address.
        value = value[1:-1]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            # inet_aton covers shortened, decimal, hexadecimal and octal IPv4
            # literals accepted by system resolvers, without performing DNS.
            address = ipaddress.IPv4Address(socket.inet_aton(value))
        except (OSError, ValueError):
            return host
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _ip_matches(host: str, patterns) -> bool:
    if isinstance(patterns, str):
        patterns = [patterns]
    # Preserve the original wildcard match as well: canonicalization must not
    # erase a deny written against an alternate literal's original spelling.
    return _matches(host, patterns) or _matches(
        _canonical_ip(host), [_canonical_ip(str(p)) for p in (patterns or [])],
    )


def host_allowed(host: str, *, tenant: str | None = "__active__", policy: dict | None = None) -> bool:
    """True iff the tenant plane permits egress to ``host``.

    Deny wins; a non-empty ``allow`` list restricts to it; no policy = allow-all.
    """
    pol = policy if policy is not None else load_tenant_egress(tenant)
    if not isinstance(pol, dict):
        return True
    if _ip_matches(host, pol.get("deny")):
        return False
    allow = pol.get("allow")
    if allow:
        return _ip_matches(host, allow)
    return True


__all__ = [
    "load_tenant_egress",
    "host_allowed",
]
