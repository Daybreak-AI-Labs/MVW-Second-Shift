"""Dashboard authentication and authorization boundary.

The global FastAPI dependency composes trusted-proxy identity, OIDC bearer and
browser sessions, SAML sessions, local invite sessions, and the static dashboard
bearer. Once any mechanism is configured, missing or invalid identity fails
closed. Principal-less local-operator compatibility is available only when auth
is genuinely off and client binding does not forbid ambient loopback trust.

Importing this module never hard-requires PyJWT: ``maverick.oidc`` lazy-imports
it only when an OIDC token is actually verified.
"""
from __future__ import annotations

import asyncio
import contextvars
import os
from contextlib import contextmanager

from fastapi import HTTPException, Request, WebSocket
from starlette.concurrency import run_in_threadpool

from maverick.config import single_read
from maverick.oidc import (
    OIDCError,
    VerifiedPrincipal,
    oidc_enabled,
    verify_oidc_token,
)
from maverick.proxy_auth import (
    principal_from_proxy,
    proxy_auth_enabled,
    proxy_header_name,
    proxy_trusts,
)

from ._request_memo import fresh_configuration, memoized

# Probe/discovery endpoints that must answer without a bearer even when OIDC is
# on (load balancers and k8s liveness/readiness probes
# can't present an ID token). Mirrors the dashboard's existing bearer-auth
# exemptions in ``app._AUTH_EXEMPT`` -- the HMAC-signed webhooks are NOT listed
# here because they carry their own credential and are gated separately.
_OIDC_EXEMPT_PATHS = frozenset(
    {
        "/healthz",
        "/livez",
        "/readyz",
        "/.well-known/agent-card.json",
        "/.well-known/agent.json",
        # Built-in browser-login endpoints must answer without an existing
        # session/bearer -- they ARE the way a browser gets one. They self-gate
        # on login_enabled() (404 when the login flow is off).
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/auth/error",
        "/auth/local-owner",
        "/auth/local-login",
        "/auth/owner-second-factor",
    }
)

# Restricted recovery authenticates each POST with the original owner's
# passphrase and fresh local policy. Exact paths; no general login bypass.
SELF_AUTH_SIGNIN_RECOVERY_PATHS = frozenset({
    "/auth/company-signin-recovery",
    "/auth/company-signin-recovery/lookup",
    "/auth/company-signin-recovery/original",
    "/auth/company-signin-recovery/review",
    "/auth/company-signin-recovery/apply",
    "/auth/company-signin-recovery/cancel",
    "/auth/company-saml-recovery",
    "/auth/company-saml-recovery/lookup",
    "/auth/company-saml-recovery/original",
    "/auth/company-saml-recovery/review",
    "/auth/company-saml-recovery/apply",
    "/auth/company-saml-recovery/cancel",
})

SELF_AUTH_WEBHOOK_PATHS = frozenset(
    {
        "/webhook/start",
        "/webhook/run",
        "/webhook/linear",
        "/webhook/jira",
        "/webhook/github",
        "/webhook/gitlab",
        "/webhook/stripe",
        # The Microsoft Teams bot: every request carries a Bot Connector JWT
        # that teams_bot verifies (issuer, audience, expiry, signing key).
        "/webhook/teams",
        # Slack interactivity and slash commands carry Slack's own v0 request
        # signature (me_api._verified_slack_body) and a replay window; Slack
        # never holds the dashboard bearer or a browser session.
        "/webhook/slack/interactions",
        "/webhook/slack/commands",
        # Phone providers use their own current check key, native caller
        # authority and durable call original, rather than a dashboard session.
        "/api/v1/channels/voice/receive",
    }
)

# Files the signed-out pages (sign-in, owner setup, invitation, public rights
# form, vendor questionnaire, shared result, sign-in error) load before any
# session exists. Each is public product code or branding and carries no data.
# Exact files only, never a folder: everything else under /static/ stays behind
# sign-in. Both gates (app._AUTH_EXEMPT and this dependency) read this one set.
PUBLIC_STATIC_PATHS = frozenset(
    {
        # The shell stylesheet: without it every signed-out page renders
        # unstyled (system serif font, full-size logo, sideways scrolling).
        "/static/second-shift.css",
        "/static/second-shift-mark.svg",
        # The self-hosted fonts second-shift.css references.
        "/static/fonts/manrope-var.woff2",
        "/static/fonts/jbm-400.woff2", "/static/fonts/jbm-500.woff2",
    }
)

_SELF_AUTH_EXEMPT_PATHS = _OIDC_EXEMPT_PATHS | PUBLIC_STATIC_PATHS | frozenset(
    {
        "/a2a/v1",
        # The LLM gateway authenticates every call with its own bearer inside
        # maverick.llm_gateway (same trust-domain rationale as /a2a/v1).
        "/gateway/v1/chat/completions",
        "/gateway/v1/messages",
        "/gateway/v1/otel",
        # A consent platform pushes consent changes with an HMAC signature
        # checked inside maverick.consent_registry; it never holds a dashboard
        # credential. Keep in step with app._AUTH_EXEMPT.
        "/consent/webhook",
    }
) | SELF_AUTH_WEBHOOK_PATHS | SELF_AUTH_SIGNIN_RECOVERY_PATHS


def route_path(connection) -> str:
    """Return the route inside the server's ASGI application mount.

    ASGI servers may retain the mount prefix in ``path``. Only the trusted
    ``root_path`` may remove that leading prefix, at a complete segment;
    forwarded headers and arbitrary matching suffixes never affect admission.
    Connections from older direct callers keep their URL path unchanged.
    """
    scope = getattr(connection, "scope", None)
    if isinstance(scope, dict):
        path = scope.get("path")
        root = scope.get("root_path", "")
    else:
        path, root = None, ""
    if path is None:
        path = getattr(getattr(connection, "url", None), "path", "")
    if not isinstance(path, str):
        return ""
    if isinstance(root, str) and root.startswith("/"):
        root = root.rstrip("/")
        if root and path == root:
            return "/"
        if root and path.startswith(root + "/"):
            return path[len(root):]
    return path


#: Load-balancer probes. They are authentication-exempt and always answer a
#: redacted payload about the process, never about a caller, so the per-request
#: identity, workspace and page-policy work does not apply to them. Doing it
#: anyway made /livez wait for a free worker thread behind slow requests.
PROBE_PATHS = frozenset({"/livez", "/readyz", "/healthz"})


class _ScopeView:
    __slots__ = ("scope",)

    def __init__(self, scope: dict) -> None:
        self.scope = scope


def probe_path(scope: dict) -> str | None:
    """The probe a plain GET or HEAD request asks for, else None."""
    if scope.get("type") != "http" or scope.get("method") not in ("GET", "HEAD"):
        return None
    path = route_path(_ScopeView(scope))
    return path if path in PROBE_PATHS else None


def _self_authenticated_path(path: str) -> bool:
    """Whether a route authenticates itself or bootstraps authentication.

    ``/api/v1/external/`` contains self-authenticating external integrations.
    Each route enforces its own scoped credential: an agent trust-registry
    credential, a signed discovery-sensor identity, or an opaque vendor-portal
    invitation (see ``external_gateway.py``). Those callers have no dashboard
    credential. ``/api/v1/public/consent`` has a separate opaque public-client
    and profile-capability contract. ``/api/v1/public/policies`` resolves an
    opaque stable link and, for private links, a separate bearer capability.
    The trailing slashes matter: the ADMIN surfaces stay under normal dashboard
    authentication."""
    return path in _SELF_AUTH_EXEMPT_PATHS or path.startswith(
        ("/share/", "/scim/", "/form/", "/dsar/response/", "/unsubscribe/", "/saml/",
         "/auth/invite/", "/api/v1/external/", "/copilot-studio/",
         "/api/v1/public/consent/", "/api/v1/public/policies/",
         "/api/v1/devices/pairing/", "/rights/", "/api/v1/public/rights/",
         # Public website chat: the publishable key and visitor session are the
         # credentials, checked in public_chat_api. The admin prefix is not listed.
         "/public/chat/v1/")
    )


def _bearer_token(request: Request) -> str:
    """Extract the raw JWT from an ``Authorization: Bearer <jwt>`` header."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return ""


def _dashboard_require_auth_enabled() -> bool:
    """Whether the dashboard's fail-closed require-auth guard is enabled."""
    env = os.environ.get("MAVERICK_DASHBOARD_REQUIRE_AUTH", "").strip().lower()
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return True
    except Exception:
        # An unreadable policy can hide ``require_auth = true``. Treat it as
        # enabled so ambiguity can never re-enable principal-less local admin.
        return True
    if not isinstance(config, dict):
        return True
    if env:
        if env in {"1", "true", "yes", "on"}:
            return True
        if env in {"0", "false", "no", "off"}:
            return False
        # A typo in an authentication-policy override is uncertainty, not an
        # instruction to restore anonymous administrator access.
        return True
    if "dashboard" not in config:
        dashboard = {}
    else:
        dashboard = config["dashboard"]
    if not isinstance(dashboard, dict):
        return True
    configured = dashboard.get("require_auth", False)
    return configured if isinstance(configured, bool) else True


def _saml_policy_configured() -> bool:
    """Whether config contains any SAML identity-policy surface.

    ``saml_enabled`` intentionally reports only a *complete* SP setup so its
    routes can remain inert while an operator fills in the template.  That is
    the wrong predicate for the local-admin compatibility exception: once a
    non-empty legacy ``[auth.saml]`` table exists, incomplete or invalid policy
    must lock anonymous access down. Explicit ``enabled = false`` is a staged
    configuration; it does not replace the installation's current sign-in.
    """
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return True
    except Exception:
        return True
    if not isinstance(config, dict):
        return True
    if "auth" not in config:
        return False
    auth = config["auth"]
    if not isinstance(auth, dict):
        return True
    if "saml" not in auth:
        return False
    saml = auth["saml"]
    if isinstance(saml, dict) and saml.get("enabled") is False:
        return False
    return bool(saml) if isinstance(saml, dict) else True


def non_static_auth_configured() -> bool:
    """Whether an identity mechanism besides the static bearer is configured.

    The static operator token and enterprise/browser identity mechanisms are
    alternatives, not mutually exclusive deployment modes. Configuration
    uncertainty reports identity policy as configured so the request reaches
    the global dependency and fails closed unless an identity verifies.
    Answered once per request (see :mod:`._request_memo`).
    """
    return memoized("non_static_auth_configured", _non_static_auth_configured)


def _non_static_auth_configured() -> bool:
    try:
        from .invites import invites_enabled
        from .local_owner import claimed
        from .saml import saml_enabled

        with single_read():
            return any((
                oidc_enabled(),
                proxy_auth_enabled(),
                invites_enabled(),
                saml_enabled(),
                _saml_policy_configured(),
                claimed(),
            ))
    except Exception:
        return True


def _proxy_principal(request: Request) -> VerifiedPrincipal | None:
    """Reverse-proxy SSO: a principal from a forwarded identity header.

    Honored ONLY when proxy auth is enabled AND the request's network peer is a
    trusted upstream (anti-spoofing -- see :mod:`maverick.proxy_auth`). Returns
    ``None`` (fall through to OIDC/loopback) when not applicable.
    """
    if not proxy_auth_enabled():
        return None
    client_host = request.client.host if request.client else ""
    if not proxy_trusts(client_host):
        return None
    value = request.headers.get(proxy_header_name(), "") or ""
    if not value:
        return None
    try:
        return principal_from_proxy(value)
    except ValueError:
        return None


def _invite_session_principal(request: Request) -> VerifiedPrincipal | None:
    """Locally-minted email-invite session identity (no-IdP mode).

    Returns a principal only when ``[dashboard] invites`` is enabled AND the
    ``ss_session`` cookie verifies against the local session secret; any
    error means None — invites must never break the auth path. Imported
    lazily like :func:`_session_principal` so the gate takes no hard
    dependency on the invites module."""
    try:
        from .invites import local_session_principal
        return local_session_principal(request)
    except Exception:  # pragma: no cover - invites must never break auth
        return None


def _session_principal(request: Request) -> VerifiedPrincipal | None:
    """Built-in browser-login identity: a valid ``ss_session`` cookie.

    Returns a principal only when the login flow is configured AND the cookie
    verifies (correct HMAC + unexpired). Absent/invalid -> ``None`` so the
    caller falls through to the OIDC bearer path unchanged. Imported lazily so
    the dashboard (and the existing bearer/proxy paths) don't take a hard
    dependency on the login module just to import this gate.
    """
    try:
        from .oidc_login import _principal_from_request_session
    except Exception:  # pragma: no cover - defensive; module should import
        return None
    return _principal_from_request_session(request)


def caller_principal(request: Request) -> str | None:
    """The full ``"user:<sub>"`` identity established on this request.

    ``None`` only means no end-user principal was established; it is not proof
    that auth is off because static-token and self-authenticated requests also
    have no user subject. Authorization helpers must prove the local exception
    through :func:`_authorization_principal` before granting operator semantics.
    """
    principal = getattr(getattr(request, "state", None), "principal", None)
    if principal is None:
        return None
    name = getattr(principal, "principal", "")
    return name if isinstance(name, str) and name else None


def constant_time_equals(supplied: str, expected: str) -> bool:
    """Constant-time equality for text a caller supplied.

    ``hmac.compare_digest`` raises ``TypeError`` for a ``str`` holding any
    non-ASCII character, which turned a crafted header or JSON field into a
    500 instead of the refusal a wrong ASCII value gets. Compare the bytes;
    ``surrogatepass`` keeps a lone surrogate distinct from every real character."""
    from maverick.constant_time import text_equals

    return text_equals(supplied, expected)


def _dashboard_token_authenticated(request) -> bool:
    """Whether this request carries the configured static dashboard bearer."""
    from ._shared import dashboard_token

    expected = dashboard_token()
    if not expected:
        return False
    authorization = request.headers.get("authorization", "")
    supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
    return bool(supplied) and constant_time_equals(supplied, expected)


def auth_genuinely_off() -> bool:
    """Whether the dashboard has no configured authentication mechanism.

    This is deliberately stricter than ``caller_principal(...) is None``:
    HMAC webhook requests are exempt from browser/OIDC authentication, and a
    static dashboard token authenticates the request without establishing an
    end-user principal. Legacy ownerless automations are safe only on a truly
    unauthenticated local deployment. Any unreadable auth configuration denies
    that legacy exception.
    """
    return memoized("auth_genuinely_off", _auth_genuinely_off)


def _auth_genuinely_off() -> bool:
    from ._shared import dashboard_token

    with single_read():
        if dashboard_token() or _dashboard_require_auth_enabled():
            return False
        return not non_static_auth_configured()


def anonymous_local_access_allowed() -> bool:
    """Whether principal-less loopback requests may act as the local operator.

    Having no configured identity mechanism is necessary but not sufficient:
    client-bound/enterprise deployments explicitly disable ambient loopback
    trust. An unreadable binding policy denies the compatibility path.
    Its own configuration reads share one current read, even inside a page
    render (``single_read(fresh=True)``). Outside an authorization boundary
    ``auth_genuinely_off`` is still answered once per request (its memo).
    """
    with single_read(fresh=True):
        if not auth_genuinely_off():
            return False
        try:
            from maverick.client import client_binding_enforced

            return not client_binding_enforced()
        except Exception:
            return False


def _authorization_principal(request: Request) -> str | None:
    """Return the caller or prove that principal-less local access is safe.

    ``None`` is an authorization grant only in genuine auth-off local mode or
    after the static dashboard bearer has authenticated the request. A missing
    proxy/OIDC/session identity must never inherit the legacy local-admin path.

    Principal-less requests recheck current local policy or the static bearer
    at every gate, including after writer waits and in retained workers.
    """
    principal = caller_principal(request)
    if principal is not None:
        return principal
    state = getattr(request, "state", None)
    with fresh_configuration(), single_read(fresh=True):
        if anonymous_local_access_allowed() or _dashboard_token_authenticated(request):
            if state is not None:
                state._anonymous_grant_verified = True
            return None
    raise HTTPException(status_code=401, detail="authenticated identity required")


_UNDECIDED = object()


def _pin_tenant_from_principal(
    request: Request, principal: VerifiedPrincipal, choice: object = _UNDECIDED,
) -> None:
    """Pin per-user isolation or an authorized workspace selection.

    HTTP middleware runs before FastAPI dependencies populate
    ``request.state.principal``, so tenant pinning must happen here, in the
    authentication dependency, immediately after a principal is established and
    before route handlers choose tenant-scoped world state. The reset token is
    stored on request state for the outer middleware to clean up after the
    response. Workspace selection is a preference, never a grant: inactive
    tenants and tenants without an effective membership remain unbound.

    ``choice`` is :func:`_tenant_pin_choice`'s answer when the caller already
    made those file reads off the event loop; the pin itself is set here, in
    the request's own context.
    """
    if choice is _UNDECIDED:
        choice = _tenant_pin_choice(request, principal)
    if choice is None or getattr(request.state, "tenant_pin_token", None) is not None:
        return
    try:
        from maverick.paths import set_tenant

        source, tenant = choice
        if source == "denied":
            request.state.workspace_tenant_denied = tenant
            return
        request.state.tenant_pin_token = set_tenant(tenant)
        request.state.workspace_tenant_source = source
        if source == "principal_selection":
            request.state.workspace_expected_tenant = tenant
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="tenant isolation policy unavailable",
        ) from exc


def _tenant_pin_choice(request: Request, principal: VerifiedPrincipal) -> tuple[str, str] | None:
    """Decide the tenant pin: ``(source, tenant)``, ``("denied", tenant)`` or None.

    Reads the configuration, the workspace selection, the tenant roster and
    the membership, so the request dependency runs it in the thread pool.
    One decision: its configuration questions share one current read.
    """
    with single_read(fresh=True):
        return _tenant_pin_choice_now(request, principal)


def _tenant_pin_choice_now(request: Request, principal: VerifiedPrincipal) -> tuple[str, str] | None:
    """This product runs one workspace, so there is no workspace selection to
    honour: the only pin is per-person isolation, when the deployment asks for it."""
    try:
        from maverick.paths import current_tenant_id, tenant_by_user_enabled

        name = getattr(principal, "principal", "")
        if not isinstance(name, str):
            name = ""
        if not name or getattr(request.state, "tenant_pin_token", None) is not None:
            return None
        # A process or deployment binding always stands.
        if current_tenant_id() is not None:
            return None
        if tenant_by_user_enabled():
            return "principal_isolation", f"api:{name}"
        return None
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="tenant isolation policy unavailable",
        ) from exc


def is_dashboard_admin(principal: str) -> bool:
    """True iff ``principal`` is a configured (bootstrap) dashboard admin.

    Admins bypass owner scoping AND department scoping (they see and control
    every goal/fleet/department). The roster is the ``[dashboard] admins`` list
    in ``~/.maverick/config.toml`` with an optional ``MAVERICK_DASHBOARD_ADMINS``
    (comma-separated) env override; comparison is exact against the full
    ``"user:<sub>"`` form.

    Single source of truth: delegates to :func:`maverick.suite_grants.is_admin_principal`
    so the dashboard HTTP gates and the kernel deploy/dispatch gates can never
    disagree about who bypasses scoping. NOTE this is the *config-pinned*
    roster, not the effective RBAC role — a user assigned ``admin`` via the
    Users page or a group mapping holds admin *permissions* but remains
    department-scoped (an admin-of-finance administers finance); only the
    config roster is the "never scoped" break-glass set.
    """
    from maverick.suite_grants import is_admin_principal
    return is_admin_principal(principal)


def global_role_for_principal(principal: str | None, *, request: Request | None = None,
                              directory: bool = False) -> str | None:
    """The principal's dashboard-wide RBAC role, ignoring tenant memberships.

    Resolution: explicit stored assignment, then the role mapped to the user's
    SCIM groups (``[dashboard] group_roles`` — team membership in the IdP), then
    the role from the caller's own sign-in claim (sign_in_roles; only when
    ``request`` is given and ``principal`` is its caller), then the configured
    default. Explicit always beats derived, so an admin can still pin an
    individual without fighting the group or claim mapping.

    ``directory`` is for work with no browser session (Teams cards, the
    other-approver rule): after the claim, the person's current Entra app roles
    are read from the directory (``maverick.entra_directory``; nothing when it
    is off or cannot be read) and mapped the same way."""
    if principal is None:
        return None
    if is_dashboard_admin(principal):
        return "admin"
    from . import rbac
    try:
        stored = rbac.get_stored_role(principal)
        if stored:
            return stored
        from . import scim_groups, strict_reads

        # An unreadable group policy must not turn its fallback viewer into
        # installation-wide authority for a workspace-only account.
        with strict_reads.strict():
            group_role = scim_groups.role_for_principal(principal)
        if group_role:
            return group_role
        from . import sign_in_roles

        # A claim role belongs to one verified sign-in: with no request
        # (background work) or for anyone but its caller there is none.
        claim_role = sign_in_roles.for_request(request, principal)
        if claim_role:
            return claim_role
        if directory:
            from maverick import entra_directory

            directory_role = entra_directory.role_for_principal(principal)
            if directory_role:
                return directory_role
        # Once workspace membership is in use, an unassigned account is not
        # implicitly entitled to the separate installation-wide namespace. The
        # durable roster remains after revocation, preventing privilege return.
        if rbac.tenant_role_scope_initialized():
            return None
        return rbac.default_role()
    except Exception:
        # A damaged role roster, group-membership source, or config default is
        # deny-all. Falling through to the historical operator default would
        # turn a policy outage into a privilege escalation.
        from . import strict_reads

        if strict_reads.active():
            raise
        return None


def role_for_principal(principal: str | None, *, request: Request | None = None,
                       directory: bool = False) -> str | None:
    """The dashboard RBAC role for ``principal``.

    None when auth is off (no principal) -- the signal for every gate to
    disable itself (single-user mode). A config-pinned bootstrap admin
    (:func:`is_dashboard_admin`) is always ``"admin"`` and cannot be demoted via
    the store, so you can't lock yourself out. Otherwise the stored role, or the
    configured default (``viewer``) for an authenticated user with no explicit
    assignment. Given the caller's own ``request``, the role from that caller's
    sign-in claim comes before the default (:func:`global_role_for_principal`);
    ``directory`` adds the role the Entra directory gives a person with no session.
    """
    if principal is None:
        return None
    if is_dashboard_admin(principal):
        return "admin"
    from . import rbac
    # Per-tenant membership wins over the global role, but only for the active
    # tenant. No active tenant or no membership -> the global behaviour below,
    # unchanged. Bootstrap admin (above) always wins, so this can't lock admins
    # out of a tenant.
    try:
        from maverick.paths import current_tenant_id
        tid = current_tenant_id()
        if tid:
            tenant_role = rbac.get_tenant_role(tid, principal)
            if tenant_role:
                return tenant_role
            from maverick.paths import tenant_by_user_enabled

            if tenant_by_user_enabled() and tid == f"api:{principal}":
                # Per-user isolation is not a shared workspace membership.
                # Keep its configured default without granting root access.
                from . import strict_reads

                with strict_reads.strict():
                    return global_role_for_principal(principal, request=request, directory=directory) or rbac.default_role()
    except Exception:
        # Never replace an unreadable tenant-local demotion with the broader
        # global/default role.
        from . import strict_reads

        if strict_reads.active():
            raise
        return None
    return global_role_for_principal(principal, request=request, directory=directory)


_DISPLAY_ROLES = contextvars.ContextVar("second_shift_display_roles", default=None)


@contextmanager
def display_role_reads():
    """Share each display role for one template render."""
    if _DISPLAY_ROLES.get() is not None:
        yield
        return
    from .rbac import display_roster_reads

    token = _DISPLAY_ROLES.set({})
    try:
        with display_roster_reads():
            yield
    finally:
        _DISPLAY_ROLES.reset(token)


def _role_of_caller(lookup, request: Request, principal: str | None) -> str | None:
    """``lookup(principal)`` for the caller of ``request``, where ``lookup`` is
    :func:`role_for_principal` or :func:`global_role_for_principal`.

    The request goes to the lookup only when that caller's own verified sign-in
    carries a claim role for it to place. A caller without one is looked up
    with the principal alone, exactly as before."""
    from . import sign_in_roles

    roles = _DISPLAY_ROLES.get()
    if roles is not None:
        from maverick.paths import explicit_tenant_id

        # The active workspace can be pinned during the request, before the
        # handler's permission checks. Keep the two authority scopes apart.
        key = (id(request.scope), explicit_tenant_id(), lookup, principal)
        if key in roles:
            return roles[key]
    if sign_in_roles.carried(request, principal) is None:
        role = lookup(principal)
    else:
        role = lookup(principal, request=request)
    if roles is not None:
        roles[key] = role
    return role


def caller_role(request: Request) -> str | None:
    """The RBAC role of the current caller (None when auth is off)."""
    with single_read(fresh=True):  # a gate: the current files, even inside a render
        return _role_of_caller(role_for_principal, request, _authorization_principal(request))


def api_key_permissions(request) -> frozenset[str] | None:
    """The permission atoms an API-key bearer may use on this request, or
    ``None`` when the request was not authenticated with an API key.

    Set by :func:`_authenticate_api_key`: the key's scopes capped by its
    owner's current role. Every RBAC gate intersects with it, so a key with
    ``tasks:read`` fails a route that requires ``operate`` even though its
    owner could call it in a browser."""
    value = getattr(getattr(request, "state", None), "api_key_permissions", None)
    return value if isinstance(value, frozenset) else None


def api_key_scopes(request) -> frozenset[str] | None:
    """Verified scope names for this API-key request, or ``None`` otherwise."""
    value = getattr(getattr(request, "state", None), "api_key_scopes", None)
    return value if isinstance(value, frozenset) else None


def _api_key_allows(request, permission: str, *, api_scope: str | None = None) -> bool:
    scoped = api_key_permissions(request)
    if scoped is None:
        return True
    if permission not in scoped:
        return False
    if permission != "operate":
        return True
    scopes = api_key_scopes(request)
    if scopes is None:
        return False
    if "admin" in scopes:
        return True
    if api_scope is None:
        # The approval queue has operator-gated reads as well as decisions and
        # claim/release actions. A task key must not borrow their shared RBAC
        # atom, while an approval key must not operate unrelated task routes.
        path = route_path(request)
        vendor_decision = (path.startswith("/api/v1/vendor-onboarding/cases/")
                           and path.endswith(("/review", "/approve-action")))
        api_scope = (
            "approvals:decide"
            if (path in {"/api/v1/approvals", "/approvals"}
                or path.startswith("/api/v1/approvals/") or vendor_decision)
            else "tasks:write"
        )
    return api_scope in scopes


def has_permission(request: Request, permission: str, *, api_scope: str | None = None) -> bool:
    """Whether the caller may perform ``permission`` ("admin"/"operate"/"view").

    Auth off -> True (legacy single-user; the local operator owns everything).
    Otherwise gated by the caller's role, and for an API-key bearer also by
    the key's scopes. A gate: it reads the current configuration once, even
    inside a page render (``single_read(fresh=True)``).
    """
    with single_read(fresh=True):
        principal = _authorization_principal(request)
        if principal is None:
            return True
        if not _api_key_allows(request, permission, api_scope=api_scope):
            return False
        from . import rbac
        return permission in rbac.permissions_for(_role_of_caller(role_for_principal, request, principal))


def _permission_denied(request: Request, permission: str, *, installation: bool = False,
                       api_scope: str | None = None) -> HTTPException:
    if not _api_key_allows(request, permission, api_scope=api_scope):
        return HTTPException(
            status_code=403,
            detail="This API key does not have a scope that allows this. "
                   "Create a key with the scope you need on your account page.",
        )
    from .access_explanations import denial
    return HTTPException(status_code=403, detail=denial(request, permission, installation=installation))


def require_permission(request: Request, permission: str, *, api_scope: str | None = None) -> None:
    """Raise ``HTTPException(403)`` unless the caller's role grants ``permission``."""
    from .execution_identity import refresh_explicit_api_key
    refresh_explicit_api_key(request)
    # The action override is meaningful only for a key bearer. Preserve the
    # ordinary two-argument role check for browser/session callers.
    allowed = (has_permission(request, permission, api_scope=api_scope)
               if api_scope is not None and api_key_permissions(request) is not None
               else has_permission(request, permission))
    if not allowed:
        raise _permission_denied(request, permission, api_scope=api_scope)


def require_workspace_picker_access(request: Request, *, write: bool = False) -> None:
    """Allow a signed-in principal to select only its own workspace.

    This narrow navigation capability does not grant access to unbound data.
    API keys retain their own view/operate scope checks.
    """
    from .execution_identity import refresh_explicit_api_key

    refresh_explicit_api_key(request)
    principal = _authorization_principal(request)
    if principal is None:
        if write:
            require_personal_write(request)
        else:
            require_permission(request, "view")
        return
    permission = "operate" if write and api_key_permissions(request) is not None else "view"
    if not _api_key_allows(request, permission):
        raise _permission_denied(request, permission)


def require_personal_write(request: Request) -> None:
    """The ``view`` floor for a person's own settings; a key also needs a write scope.

    Everyone signed in changes their own choices at the view floor. A bearer key
    acts as its owner, so a read-only key must not change the owner's account
    (chat links, the daily-summary address, the workspace picker)."""
    require_permission(request, "view")
    if api_key_permissions(request) is not None:
        require_permission(request, "operate")


def has_global_permission(request: Request, permission: str) -> bool:
    """Whether the caller may perform a dashboard-wide control-plane action.

    Tenant memberships are intentionally ignored so a tenant-local admin cannot
    satisfy global admin gates for other tenants or dashboard settings. A gate:
    it reads the current configuration once (``single_read(fresh=True)``).
    """
    with single_read(fresh=True):
        principal = _authorization_principal(request)
        if principal is None:
            return True
        if not _api_key_allows(request, permission):
            return False
        from . import rbac

        return permission in rbac.permissions_for(_role_of_caller(global_role_for_principal, request, principal))


def require_global_permission(request: Request, permission: str) -> None:
    """Raise ``HTTPException(403)`` unless the global role grants permission."""
    from .execution_identity import refresh_explicit_api_key
    refresh_explicit_api_key(request)
    if not has_global_permission(request, permission):
        raise _permission_denied(request, permission, installation=True)


def require_page_permission(request: Request, path: str) -> None:
    """Apply a registered page's security floor to a backing API read.

    Page-visibility overrides only control navigation and HTML admission;
    they do not revoke the underlying role permission or API-key scope.
    """
    from . import ui_visibility

    page = ui_visibility.page_for(path)
    if page is None or page["path"] != path:
        raise RuntimeError(f"no exact page security floor for {path}")
    if page.get("scope") == "global":
        require_global_permission(request, page["floor"])
    else:
        require_permission(request, page["floor"])


def _enforce_scim_active(principal: VerifiedPrincipal) -> None:
    """Reject a SCIM-matched principal that has been deprovisioned.

    Revocation epochs terminate credentials minted before deprovisioning, but
    an IdP that mistakenly continues issuing fresh tokens could otherwise give
    the inactive user the dashboard's global default role. The live SCIM roster
    is therefore an authentication gate as well as a group-grant source.
    """
    try:
        from .scim_groups import active_for_principal

        active = active_for_principal(principal.principal)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="identity lifecycle policy unavailable",
        ) from exc
    if active is False:
        raise HTTPException(status_code=401, detail="invalid identity")


_BREAK_GLASS_AUDIT_INTERVAL = 3600.0
_break_glass_last_audit: list[float | None] = [None]


def _audit_break_glass(connection) -> None:
    """Require an audit record for every write and sample read-only requests."""
    import time as _time

    now = _time.monotonic()
    last = _break_glass_last_audit[0]
    sampled_read = getattr(connection, "method", None) in {"GET", "HEAD", "OPTIONS"}
    if sampled_read and last is not None and now - last < _BREAK_GLASS_AUDIT_INTERVAL:
        return
    from maverick.audit import EventKind, audit_event

    client = connection.client.host if getattr(connection, "client", None) else ""
    path = str(getattr(getattr(connection, "url", None), "path", "") or "")
    if not audit_event(EventKind.BREAK_GLASS_TOKEN_USED, agent="static-dashboard-operator",
                       path=path, client=client or "", method=getattr(connection, "method", "WEBSOCKET")):
        raise HTTPException(
            status_code=503,
            detail="The activity record is unavailable, so the dashboard token cannot be used right now.",
        )
    # Start the window only once a row exists: a refused audit leaves it open so
    # the next request is refused too instead of being admitted unrecorded.
    if sampled_read:
        _break_glass_last_audit[0] = now


def _api_key_bearer(connection) -> str:
    """The presented bearer when it has the API-key shape, else ``""``."""
    token = _bearer_token(connection)
    if not token:
        return ""
    try:
        from .api_keys import looks_like_key

        return token if looks_like_key(token) else ""
    except Exception:
        return ""


def _resolve_websocket_principal(websocket) -> VerifiedPrincipal | None:
    """Authenticate a WebSocket handshake with the configured mechanisms."""
    if websocket is None:
        if anonymous_local_access_allowed():
            return None
        raise HTTPException(status_code=401, detail="authenticated identity required")

    # Explicit credentials take precedence over ambient proxy/cookie identity.
    # Otherwise an invalid bearer could be ignored and the handshake satisfied
    # by a browser session riding on the same request.
    authorization = websocket.headers.get("authorization", "")
    if authorization:
        if _dashboard_token_authenticated(websocket):
            _audit_break_glass(websocket)
            return None
        ws_token = _bearer_token(websocket)
        if not ws_token or not oidc_enabled():
            raise HTTPException(status_code=401, detail="invalid bearer credential")
        try:
            ws_principal = verify_oidc_token(ws_token)
        except OIDCError as exc:
            raise HTTPException(status_code=401, detail="invalid OIDC token") from exc
        from .m365_copilot_api import has_copilot_scope

        if has_copilot_scope(ws_principal):
            raise HTTPException(403, "This sign-in is for Second Shift's Copilot summaries.")
        from .session_revocation import is_revoked
        if is_revoked(ws_principal.sub, ws_principal.claims.get("iat")):
            raise HTTPException(status_code=401, detail="invalid OIDC token")
        _enforce_scim_active(ws_principal)
        from . import sign_in_roles

        return sign_in_roles.with_token_role(ws_principal)

    # Proxy/session identities are valid WebSocket credentials too. Their
    # browser Origin is checked by ``websocket_authorized`` before accept.
    pp = _proxy_principal(websocket)
    if pp is not None:
        _enforce_scim_active(pp)
        return pp
    sp = _session_principal(websocket)
    if sp is not None:
        _enforce_scim_active(sp)
        return sp
    lp = _invite_session_principal(websocket)
    if lp is not None:
        _enforce_scim_active(lp)
        return lp

    if oidc_enabled():
        raise HTTPException(status_code=401, detail="OIDC bearer token required")
    if not anonymous_local_access_allowed():
        raise HTTPException(status_code=401, detail="authenticated identity required")
    return None


def _authenticate_oidc_bearer(request: Request, token: str) -> VerifiedPrincipal:
    """Verify an explicit HTTP OIDC bearer without binding request ContextVars."""
    try:
        principal = verify_oidc_token(token)
    except OIDCError as exc:
        # Opaque 401: never leak which check failed (expiry vs. signature vs.
        # audience) to an unauthenticated caller.
        raise HTTPException(
            status_code=401,
            detail="invalid OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    from .m365_copilot_api import PREFIX, has_copilot_scope

    if has_copilot_scope(principal) and (
        not route_path(request).startswith(PREFIX + "/") or request.method not in {"GET", "HEAD"}
    ):
        raise HTTPException(403, "This sign-in is for Second Shift's Copilot summaries.")
    # Revocation: a bearer issued before the principal's revocation epoch
    # ("log out everywhere" / SCIM deprovision) is rejected even if it verifies.
    from .session_revocation import is_revoked
    if is_revoked(principal.sub, principal.claims.get("iat")):
        raise HTTPException(
            status_code=401, detail="invalid OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    _enforce_scim_active(principal)
    from . import sign_in_roles

    # The app roles in this verified token count for this request only.
    return sign_in_roles.with_token_role(principal)


def _resolve_principal(
    request: Request = None,  # type: ignore[assignment]
    websocket: WebSocket = None,  # type: ignore[assignment,name-defined]
) -> VerifiedPrincipal | None:
    """Authenticate every non-exempt HTTP or WebSocket request.

    An explicit static/OIDC bearer takes precedence so an invalid credential
    cannot borrow ambient authority. Without one, trusted proxy identity is
    followed by a verified browser or invite session. Missing identity is
    allowed only in genuine local auth-off mode. Probe,
    discovery, login-bootstrap, share, SCIM, SAML, form, and webhook paths carry
    their own narrower credential or are intentionally public bootstrap routes.
    The whole resolution reads the current configuration once
    (``single_read(fresh=True)``).
    """
    with single_read(fresh=True):
        return _resolve_principal_now(request, websocket)


def _resolve_principal_now(request, websocket) -> VerifiedPrincipal | None:
    if request is None:
        return _resolve_websocket_principal(websocket)

    # An explicit bearer is non-ambient API authority. Resolve it before
    # proxy/browser sessions so the middleware's CSRF exemption cannot be
    # triggered by an invalid header and then satisfied by an ambient cookie.
    # Self-authenticated routes keep their own credential contract. A valid
    # static dashboard bearer has local-operator semantics; any other bearer
    # must verify as OIDC or fail instead of falling back to ambient identity.
    path = route_path(request)
    self_authenticated = _self_authenticated_path(path)
    if path.startswith("/api/v1/external/"):
        return None  # Gateway credentials are independent of browser workspace selection.
    authorization = request.headers.get("authorization", "")
    if not self_authenticated and authorization:
        if _dashboard_token_authenticated(request):
            _audit_break_glass(request)
            return None
        explicit_token = _bearer_token(request)
        if explicit_token and oidc_enabled():
            return _authenticate_oidc_bearer(request, explicit_token)
        raise HTTPException(
            status_code=401,
            detail="invalid bearer credential",
            headers={"WWW-Authenticate": "Bearer"},
        )

    pp = _proxy_principal(request)
    if pp is not None:
        _enforce_scim_active(pp)
        return pp

    # OIDC and SAML mint the same signed browser session. Check it before the
    # protocol switches so a SAML-only deployment (and a proxy+session fallback)
    # cannot degrade to an anonymous local operator.
    sp = _session_principal(request)
    if sp is not None:
        _enforce_scim_active(sp)
        return sp

    # Email-invite local sessions use the same cookie name but their own issuer.
    # Accept only a fully verified, unrevoked session before considering any
    # anonymous compatibility path.
    lp = _invite_session_principal(request)
    if lp is not None:
        _enforce_scim_active(lp)
        return lp

    if self_authenticated:
        return None

    if not oidc_enabled():
        # ``None`` may mean local-admin only when *every* auth mechanism is off.
        # Proxy, SAML, invites, require_auth, or an unreadable auth config all
        # turn a missing/invalid identity into a 401 at the global dependency,
        # including routes that happen not to call an RBAC helper themselves.
        if not anonymous_local_access_allowed():
            raise HTTPException(status_code=401, detail="authenticated identity required")
        return None

    token = _bearer_token(request)
    if not token:
        raise HTTPException(
            status_code=401,
            detail="OIDC bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _authenticate_oidc_bearer(request, token)


def _enforce_workspace_policies(connection, principal) -> None:
    """Policies that need the caller's workspace: its allowed addresses and
    its second-factor requirement (the workspace's config overlay is active
    once the tenant is pinned). Sign-in bootstrap and sign-out paths are
    skipped so a refused session can still end itself. One gate: both read
    the current configuration once (``single_read(fresh=True)``)."""
    path = route_path(connection)
    if _self_authenticated_path(path):
        return
    from .ip_allowlist import BLOCKED_MESSAGE, workspace_allows
    from .mfa_policy import enforce_session_policy

    with single_read(fresh=True):
        if not workspace_allows(connection):
            raise HTTPException(status_code=403, detail=BLOCKED_MESSAGE)
        enforce_session_policy(principal)


def _bind_identity(connection, principal, pin_choice: object = _UNDECIDED) -> bool:
    """Set the identity and tenant pin; True when workspace policies apply."""
    if connection is None or principal is None:
        return False
    connection.state.principal = principal
    _pin_tenant_from_principal(connection, principal, pin_choice)
    return True


# Despite the names, these limits (and the "identity verification is busy"
# answer) apply to every bearer that is not the static dashboard token: API
# keys and paired-device tokens as well as OIDC tokens. Which kind a bearer is
# becomes known only once verification has started.
_OIDC_VERIFY_SLOTS = 8
_OIDC_ADMISSION_SECONDS = 0.25


async def _verify_off_loop(request, websocket):
    connection = request if request is not None else websocket
    explicit = connection is not None and connection.headers.get("authorization", "")
    remote_bearer = (explicit and not _dashboard_token_authenticated(connection)
                     and (request is None or not _self_authenticated_path(route_path(request))))
    if not remote_bearer:
        return await run_in_threadpool(_resolve_principal, request=request, websocket=websocket)
    # Cap potentially remote verification before borrowing a worker. Probes and
    # local/session authentication retain worker capacity during a slow IdP.
    loop = asyncio.get_running_loop()
    limiter = getattr(loop, "_second_shift_oidc_slots", None)
    if limiter is None:
        limiter = asyncio.Semaphore(_OIDC_VERIFY_SLOTS)
        loop._second_shift_oidc_slots = limiter
    try:
        await asyncio.wait_for(limiter.acquire(), timeout=_OIDC_ADMISSION_SECONDS)
    except TimeoutError as exc:
        raise HTTPException(status_code=503, detail="identity verification is busy",
                            headers={"Retry-After": "1"}) from exc
    worker = asyncio.create_task(run_in_threadpool(_resolve_principal, request=request, websocket=websocket))

    def finished(task):
        limiter.release()
        if not task.cancelled():
            task.exception()  # retrieve failures when the client left during verification

    worker.add_done_callback(finished)
    # A disconnected request cannot release admission while its resolver thread
    # is still running. It also cannot bind a late identity into another request.
    return await asyncio.shield(worker)


async def require_principal_in_request_context(
    request: Request = None,  # type: ignore[assignment]
    websocket: WebSocket = None,  # type: ignore[assignment]
) -> VerifiedPrincipal | None:
    """Verify off-loop, then bind identity and tenant in the original task.

    Only cryptographic public keys are cached. Session revocation and identity
    lifecycle are checked on every verification; tenant selection/membership is
    resolved at binding, so cached keys never become an authorization grant.
    """
    if request is not None and (
        probe_path(getattr(request, "scope", None) or {})
        or route_path(request).startswith("/api/v1/external/ekko/")
    ):
        return None  # probes and recorder routes have no browser principal
    principal = await _verify_off_loop(request, websocket)
    connection = request if request is not None else websocket
    pin_choice: object = _UNDECIDED
    if (connection is not None and principal is not None
            and getattr(connection.state, "paired_device_verified", False) is not True):
        # The workspace selection, roster and membership are file reads: decide
        # in the thread pool, then pin in this request's own context.
        pin_choice = await run_in_threadpool(_tenant_pin_choice, connection, principal)
    if _bind_identity(connection, principal, pin_choice):
        # The policies read the configuration (the workspace's overlay once the
        # tenant is pinned, which the thread's copied context carries): keep
        # that file I/O off the event loop.
        await run_in_threadpool(_enforce_workspace_policies, connection, principal)
    return principal
