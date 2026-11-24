"""Per-tool network egress policy (allow/deny hosts).

Declarative egress control so a tool can be restricted to a set of hosts:

    [sandbox.tool.http_fetch]
    allow_egress = ["api.github.com", "*.openai.com"]

    [sandbox.tool.shell]
    deny_egress = ["*"]

``host_allowed(tool, host, policy)`` is the pure decision (fnmatch globs; deny
wins over allow; empty/absent policy = allow-all, preserving current behavior).
This module is the *policy layer*. Enforcement today is application-layer: the
built-in HTTP tools/connectors and ``tenant.egress`` consult this decision
before dialing a host. There is NO packet-level (iptables/nftables) firewall
backend yet, so a tool that bypasses the HTTP layer (e.g. raw shell) is not
constrained by this policy. The decision is unit-tested in isolation.

**Network posture** (``[security] network_policy``, Settings > All settings):
``"open"`` (the default, and what an unset key means), ``"allowlist"`` or
``"deny-all"``. It is enforced, never just displayed, and only ever narrows
what the rules above allow:

* ``deny-all`` -- the web tools (:data:`WEB_TOOLS`) are removed from every
  agent's tool list, and the work area gets no network (see
  :func:`work_area_offline`).
* ``allowlist`` -- web requests reach only hosts on an approved list (a tool's
  ``allow_egress`` or ``[egress] allow``; with no list nothing is approved),
  the web tools that cannot be held to a list (:data:`UNLISTABLE_TOOLS`) are
  removed, and the work area gets no network.
* A value this module does not know fails closed to ``deny-all``.

``[sandbox] network_policy = "deny-all"`` asserts the same no-network rule for
the work area alone (the Kubernetes backend then verifies its deny-all
NetworkPolicy before every command); a value it does not know does too.
"""
from __future__ import annotations

from fnmatch import fnmatch


def _canonical_dns_name(name: str) -> str:
    """Return a DNS name in policy-comparison form.

    DNS names may be written with a final root-label dot (for example,
    ``example.com.``), but that is equivalent to ``example.com`` for lookup
    purposes.  Canonicalize both request hosts and policy patterns so deny
    rules cannot be bypassed with the fully-qualified spelling.
    """
    value = (name or "").strip().lower()
    value = value.removesuffix(".")
    labels = []
    for label in value.split("."):
        if any(ch in label for ch in "*?["):
            labels.append(label)
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def _matches(host: str, patterns) -> bool:
    # A hand-edited config may give a bare string (``deny_egress = "*"``) instead
    # of a list. Iterating a string yields its characters, so a string deny rule
    # would silently never match -- a fail-OPEN on the security-critical deny
    # path. Treat a lone string as a single-pattern list.
    if isinstance(patterns, str):
        patterns = [patterns]
    h = _canonical_dns_name(host)
    return any(fnmatch(h, _canonical_dns_name(str(p))) for p in (patterns or []))


__all__ = [
]
