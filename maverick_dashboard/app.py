"""FastAPI dashboard for Second Shift.

Goals run through the shared BackgroundTask runner in ``maverick.runner``,
which the REST API and the MCP server use too.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
import weakref
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__ as _dashboard_version
from . import auth_metrics as _auth_metrics
from ._shared import _world
from ._shared import dashboard_token as _dashboard_token
from .api import router as api_router
from .auth import (
    PUBLIC_STATIC_PATHS,
    SELF_AUTH_SIGNIN_RECOVERY_PATHS,
    SELF_AUTH_WEBHOOK_PATHS,
    caller_role,
    constant_time_equals,
    has_global_permission,
    has_permission,
    non_static_auth_configured,
    probe_path,
    require_permission,
    require_principal_in_request_context,
    route_path,
)
from .oidc_login import router as oidc_login_router
from .route_identity import (
    stabilize_effective_route_names as _stabilize_effective_route_names,
)
from .static_asset_versioning import AssetVersionExtension, AssetVersions, StaticCacheMiddleware
from .template_runtime import (
    _format_datetime as _format_datetime,
)
from .template_runtime import (
    _template_bytecode_cache as _template_bytecode_cache,
)
from .template_runtime import (
    _Templates as _Templates,
)
from .template_runtime import (
    _templates_auto_reload as _templates_auto_reload,
)

log = logging.getLogger(__name__)


class _CallbackAccessLogFilter(logging.Filter):
    """Remove callback queries before Uvicorn handlers or formatters see them."""

    _second_shift_callback_redaction = True

    def filter(self, record):
        args = record.args
        # Both Uvicorn HTTP implementations emit this structured access record.
        # Keep method, route and status useful without changing the ASGI request:
        # the authorization handler still needs the original one-time values.
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            path, separator, _query = args[2].partition("?")
            # Suffix matching also covers an application mounted under a prefix.
            # Login can carry a nested callback query in its return_to parameter.
            if separator and unquote(path).rstrip("/").endswith(
                ("/connections", "/auth/login", "/auth/callback", "/flow/approve")
            ):
                record.args = (*args[:2], f"{path}?[redacted]", *args[3:])
        return True


# Logger filters survive Uvicorn's default dictConfig. Installing at app import
# covers CLI/desktop (app imported first), direct Uvicorn import strings (logging
# configured first), and JSON logging with propagation to the configured root.
_access_logger = logging.getLogger("uvicorn.access")
if not any(getattr(item, "_second_shift_callback_redaction", False) for item in _access_logger.filters):
    _access_logger.addFilter(_CallbackAccessLogFilter())

TEMPLATES_DIR = Path(__file__).parent / "templates"


templates = _Templates(directory=str(TEMPLATES_DIR))
# Starlette builds the Environment itself; both are plain Environment
# attributes read at get_template time.
templates.env.auto_reload = _templates_auto_reload()
templates.env.bytecode_cache = _template_bytecode_cache()


templates.env.filters["datetime"] = _format_datetime
# Human-friendly identities and roles: never show a raw OIDC sub or a lowercase
# role slug in the UI. `identity` returns an object with .name/.detail/.raw/.kind.
from . import identity_format as _idfmt  # noqa: E402

templates.env.filters["identity"] = _idfmt.humanize_principal
templates.env.filters["role_label"] = _idfmt.role_label
templates.env.filters["permission_label"] = _idfmt.permission_label
templates.env.filters["humanize"] = _idfmt.humanize
templates.env.filters["job_title"] = _idfmt.job_title
templates.env.filters["known_label"] = _idfmt.known_label
# Plain labels for model ids, setting sources and sizes (administration pages).
from . import plain_labels as _plain_labels  # noqa: E402

_plain_labels.register(templates.env)
# Make `theme` available unconditionally so templates rendered without
# a Request object (rare; legacy paths) still resolve `theme or 'dark'`.
templates.env.globals.setdefault("theme", "dark")
templates.env.globals.setdefault("font", "default")
templates.env.globals.setdefault("lang", "en")
templates.env.globals.setdefault("page_lang", "en")
templates.env.globals.setdefault("density", "comfortable")
templates.env.globals.setdefault("glass", "off")
templates.env.globals.setdefault("custom_theme_css", "")
templates.env.globals.setdefault("custom_theme_names", [])
templates.env.globals.setdefault("dir", "ltr")

# Content-versioned static URLs refresh when bundled file metadata changes.
# Matching public versions may be cached for a year; canonical/stale script
# and stylesheet URLs revalidate. Missing files are checked again next time.
_asset_versions = AssetVersions(Path(__file__).parent / "static")


def static_version(name: str) -> str:
    """Return the current content hash for a bundled public asset."""
    return _asset_versions.version(name)


def static_url(name: str) -> str:
    """``/static/<name>?v=<hash>`` for a bundled asset (plain path if unknown)."""
    version = static_version(name)
    return f"/static/{name}?v={version}" if version else f"/static/{name}"


templates.env.globals["static_url"] = static_url
templates.env.add_extension(AssetVersionExtension)
templates.env.globals.setdefault("ul", lambda source: "en")


# Context processor: every template gets the `theme` variable for the
# body class + the theme switcher links, the `font` accessibility axis,
# and the chrome-i18n helpers (`lang`, `t`).
def _theme_context(request: Request) -> dict:
    from .i18n import t as _t
    from .i18n_journeys import context as journey_context

    return {
        "theme": "dark",
        "theme_color": "#04050A",
        "font": "default",
        "density": "comfortable",
        "glass": "off",
        "custom_theme_css": "",
        "custom_theme_names": [],
        "lang": "en",
        "page_lang": "en",
        "dir": "ltr",
        "t": lambda key: _t(key, "en"),
        **journey_context(request, "en"),
    }


# Register the per-request context processor with Starlette so every
# TemplateResponse picks up the resolved theme automatically.
templates.context_processors.append(_theme_context)


# Context processor: every page template gets this response's CSP script nonce
# (drawn per request by security_headers) for its inline <script> tags.
def _csp_nonce_context(request: Request) -> dict:
    return {"csp_script_nonce": getattr(request.state, "csp_script_nonce", "")}


templates.context_processors.append(_csp_nonce_context)


# Context processor: every template gets `nav_groups` -- the sidebar filtered
# to the pages the caller's RBAC role may see (defaults + the admin's Settings
# overrides; see maverick_dashboard.ui_visibility). Auth off -> full nav,
# exactly as before.
def _page_role(request: Request, *, global_scope: bool = False) -> str | None:
    """Reserve None/full navigation for a verified principal-less grant.

    Role resolution also returns None when a signed-in user's policy cannot
    be read. That case has no permissions, unlike the local/static-token
    compatibility grant which caller_role validates before returning.
    """
    from . import auth

    try:
        principal = auth.caller_principal(request)
        role = (
            auth._role_of_caller(auth.global_role_for_principal, request, principal)
            if global_scope and principal is not None else caller_role(request)
        )
        if role is None and principal is not None:
            return ""
        return role
    except Exception:
        return ""


def _nav_context(request: Request) -> dict:
    """The navigation's permission and role checks share one current read
    (``single_read(fresh=True)``), even inside the page render's own read."""
    from maverick.config import single_read

    with single_read(fresh=True):
        return _nav_context_now(request)


def _nav_context_now(request: Request) -> dict:
    from . import ui_visibility
    from .halt_policy import shared_halt_backend as _shared_halt_backend

    role = _page_role(request)
    scope_roles = {"global": _page_role(request, global_scope=True)}
    groups = ui_visibility.nav_groups(role, scope_roles=scope_roles)
    finder = ui_visibility.finder_pages(role, scope_roles=scope_roles)
    finder_hrefs = {link["href"] for group in finder for link in group["links"]}

    def can_open_page(path: str) -> bool:
        """In-page links to another screen appear only for people that screen admits."""
        page = ui_visibility.page_for(path.split("#")[0].split("?")[0])
        return page is not None and page["path"] in finder_hrefs
    # The emergency stop follows the API's own rule, so the shell never offers
    # a control the API would refuse.
    try:
        can_halt = (
            has_global_permission(request, "admin")
            if _shared_halt_backend()
            else has_global_permission(request, "respond")
        )
    except Exception:  # pragma: no cover -- shell rendering stays fail-closed
        can_halt = False
    try:
        from .oidc_login import browser_session_enabled

        show_logout = browser_session_enabled()
    except Exception:  # pragma: no cover -- shell rendering stays fail-soft
        show_logout = False
    try:
        viewer_global_admin = has_global_permission(request, "admin")
    except Exception:  # pragma: no cover -- shell rendering stays fail-closed
        viewer_global_admin = False
    return {
        "viewer_global_admin": viewer_global_admin,
        "nav_groups": groups,
        "finder_pages": finder,
        "can_open_page": can_open_page,
        "can_halt": can_halt,
        "show_logout": show_logout,
        "nav_where": _nav_where(request, groups, finder),
    }


def _nav_where(request, groups, finder):
    from . import ui_visibility
    try:
        return ui_visibility.where(request.url.path, groups, finder)
    except Exception:  # pragma: no cover -- shell rendering never fails on it
        return None


templates.context_processors.append(_nav_context)
# Requestless renders cannot prove authority; the request processor supplies
# permitted destinations, including full navigation in verified local mode.
templates.env.globals.setdefault("nav_groups", [])
templates.env.globals.setdefault("finder_pages", [])
templates.env.globals.setdefault("can_open_page", lambda path: False)


def _require_auth_enabled() -> bool:
    """Opt-in guard: refuse to serve the dashboard with no auth configured.
    ``MAVERICK_DASHBOARD_REQUIRE_AUTH`` env wins over ``[dashboard] require_auth``;
    off by default so the single-tenant local flow is unchanged."""
    env = os.environ.get("MAVERICK_DASHBOARD_REQUIRE_AUTH", "").strip().lower()
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return True
    except Exception:
        # A malformed/unreadable config may conceal ``require_auth = true``.
        # Treat ambiguity as required so startup cannot silently enable local
        # administrator access.
        return True
    if not isinstance(config, dict):
        return True
    if env:
        if env in {"1", "true", "yes", "on"}:
            return True
        if env in {"0", "false", "no", "off"}:
            return False
        return True
    if "dashboard" not in config:
        dashboard = {}
    else:
        dashboard = config["dashboard"]
    if not isinstance(dashboard, dict):
        return True
    configured = dashboard.get("require_auth", False)
    return configured if isinstance(configured, bool) else True


def _assert_dashboard_auth_configured() -> None:
    """When ``require_auth`` is set, refuse to boot if NO auth mechanism is
    configured (token, OIDC, proxy SSO, invites, or complete SAML), so an operator
    who asked for auth can never accidentally serve the (loopback) control
    surface unauthenticated. No-op unless ``require_auth`` is explicitly on, so
    a fresh single-tenant install is never locked out."""
    if not _require_auth_enabled():
        return
    if _dashboard_token():
        return
    try:
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            return
    except Exception:  # pragma: no cover
        pass
    try:
        from maverick.proxy_auth import proxy_auth_enabled

        if proxy_auth_enabled():
            return
    except Exception:  # pragma: no cover
        pass
    try:
        # Email-invite local sessions count as a configured mechanism: with
        # require_auth on, only a verified invite-minted session (or one of the
        # modes above) passes the middleware — everything else 401s.
        from .invites import invites_enabled

        if invites_enabled():
            return
    except Exception:  # pragma: no cover
        pass
    try:
        # SAML uses the same signed browser session as OIDC, so a complete SAML
        # configuration is a first-class authentication mechanism too.
        from .saml import _session_secret, saml_enabled

        if saml_enabled() and _session_secret():
            return
    except Exception:  # pragma: no cover
        pass
    raise RuntimeError(
        "[dashboard] require_auth is set, but no auth mechanism is configured. "
        "Set MAVERICK_DASHBOARD_TOKEN, enable OIDC ([auth.oidc]), enable "
        "reverse-proxy SSO ([auth.proxy]), enable SAML ([auth.saml]), or enable "
        "email invites ([dashboard] invites) -- refusing to serve the dashboard "
        "unauthenticated."
    )


async def _drift_check_loop() -> None:
    """Compare every enrolled outside agent with its baseline on a timer.

    New findings are audited and alerted by the check itself. A failed pass is
    logged and the loop carries on; it never stops the app.
    """
    while True:
        minutes = 15
        try:
            from maverick import agent_drift

            minutes = agent_drift.settings().get("check_minutes", 15)
            if agent_drift.enabled():
                await run_in_threadpool(agent_drift.check_all)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("scheduled agent drift check failed", exc_info=True)
        await asyncio.sleep(max(1, int(minutes)) * 60)


async def _platform_check_loop() -> None:
    """Ask each configured platform which agents it has, on a timer.

    What a platform reports is compared with enrollment by the check itself. A
    failed pass is logged and the loop carries on; it never stops the app.
    The first pass waits a moment, so starting the app never begins with
    calls to other systems.
    """
    await asyncio.sleep(60)
    while True:
        minutes = 60
        try:
            from maverick import agent_watch

            minutes = agent_watch.settings().get("sync_minutes", 60)
            if agent_watch.enabled():
                await run_in_threadpool(agent_watch.sync)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("scheduled platform check failed", exc_info=True)
        await asyncio.sleep(max(1, int(minutes)) * 60)


async def _expiry_reminder_loop() -> None:
    """Remind people before a waiting request or an access key runs out.

    What was sent is recorded by the check itself, so a restart sends nothing
    twice. A failed pass is logged and the loop carries on."""
    await asyncio.sleep(30)
    while True:
        try:
            from maverick import expiry_reminders

            await run_in_threadpool(expiry_reminders.check_all)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("scheduled expiry reminders failed", exc_info=True)
        await asyncio.sleep(300)


async def _owner_note_loop() -> None:
    """Send each agent owner the weekly note of what needs them.

    What was sent is recorded by the pass itself, so a restart sends nothing
    twice. A failed pass is logged and the loop carries on."""
    await asyncio.sleep(90)
    while True:
        try:
            from maverick import owner_note

            await run_in_threadpool(owner_note.run_due)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("scheduled owner note failed", exc_info=True)
        await asyncio.sleep(300)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Start-up and shut-down for the web app.

    Two start-up checks abort on purpose: a second process must not write the
    same data folder (records are hash-chained and assume one writer), and the
    app must not serve without sign-in configured.
    """
    import contextlib
    from functools import partial

    from maverick.control_plane_lease import acquire as _acquire_control_plane
    from maverick.control_plane_lease import current, release
    from maverick.postgres_transactions import close_postgres_pools, open_postgres_pools

    owns_lease = current() is None
    _acquire_control_plane(role="dashboard")
    try:
        _assert_dashboard_auth_configured()
        open_postgres_pools()
        try:
            from maverick.proxy_auth import warn_if_untrusted_proxy_config

            warn_if_untrusted_proxy_config()
        except Exception:  # pragma: no cover -- a warning must never block startup
            pass
        try:
            from maverick.ops_alert import warn_if_alerts_cannot_reach_anyone

            warn_if_alerts_cannot_reach_anyone()
        except Exception:  # pragma: no cover -- a warning must never block startup
            pass
        timers = [asyncio.create_task(_drift_check_loop()), asyncio.create_task(_platform_check_loop()),
                  asyncio.create_task(_expiry_reminder_loop()), asyncio.create_task(_owner_note_loop())]
        try:
            yield
        finally:
            for timer in timers:
                timer.cancel()
            for timer in timers:
                with contextlib.suppress(asyncio.CancelledError):
                    await timer
    finally:
        await run_in_threadpool(partial(close_postgres_pools, timeout=5))
        if owns_lease:
            release()


def enforce_page_visibility(
    request: Request = None,  # type: ignore[assignment]
) -> None:
    """App-level dependency: 403 a UI page hidden for the caller's RBAC role.

    Runs AFTER ``require_principal`` (dependency order), so the verified
    principal is already on ``request.state``. Visibility (defaults + the
    admin's Settings overrides) governs registered page paths and their
    subpaths only -- /api, webhooks, share links, auth and probe endpoints are
    unregistered and untouched. Auth off (no principal -> role None) is a
    no-op, preserving single-user local mode; hiding the nav entry alone would
    be cosmetic, this makes the hidden page unreachable too.
    """
    if request is None:  # WebSocket connection -- page policy doesn't apply
        return
    from . import auth as auth_boundary

    # A route that carries its own credential (the signed consent webhook) has
    # no dashboard role to compare against the page policy of its parent page.
    if auth_boundary._self_authenticated_path(route_path(request)):
        return
    if route_path(request) == "/workspace/tenant":
        # The picker is the recovery path for authenticated workspace members
        # who intentionally have no authority in the unbound namespace.
        auth_boundary.require_workspace_picker_access(request)
        return
    require_page_visible(request, route_path(request))


async def _page_visibility(request: Request = None) -> None:  # type: ignore[assignment]
    """The app-level page-policy dependency: the check reads the settings, so
    it runs in the worker pool, except for a probe, which is no page."""
    if request is None or probe_path(request.scope):
        return
    await run_in_threadpool(enforce_page_visibility, request)


def page_visible(request: Request, path: str) -> bool:
    """Whether the page governing ``path`` admits the caller: the same rule
    :func:`enforce_page_visibility` applies to every request for it."""
    from . import ui_visibility

    page = ui_visibility.page_for(path)
    if page is None:
        return True
    role = _page_role(request, global_scope=page.get("scope") == "global")
    return ui_visibility.is_visible(page, role)


def require_page_visible(request: Request, path: str) -> None:
    """403 unless the page governing ``path`` admits the caller. A page that
    shows another page's content at a new address checks the old page here,
    so a merged view never admits more (or fewer) people than before."""
    if not page_visible(request, path):
        raise HTTPException(status_code=403, detail="this page is not enabled for your role")


# Public submission routes write to the workspace their link names (a form
# token, a rights-request page), never to the visitor's selected workspace, and
# accept submissions from people without a session. The stale-tab check has
# nothing to protect there; it only refused a signed-in person testing a form.
_PUBLIC_SUBMISSION_ROUTES = frozenset({
    "/form/{token}",
    "/api/v1/public/rights/{slug}/requests",
    "/api/v1/public/rights/verify/{token}",
})


async def enforce_expected_workspace_tenant(
    request: Request = None,  # type: ignore[assignment]
) -> None:
    """Reject a stale browser mutation after the selected workspace changed.

    Each rendered page carries the tenant it was rendered under. The shared UI
    client adds that value to fetches and native forms. Comparing it after
    authentication has established the request's current principal-scoped
    selection prevents an old tab from silently writing into a newly selected
    tenant. Bearer/API clients and public cross-origin contracts remain on their
    explicit authority paths and are not made dependent on browser state.
    """
    if request is None or request.method in _CSRF_SAFE_METHODS:
        return
    route = request.scope.get("route")
    if getattr(route, "path", None) in _PUBLIC_SUBMISSION_ROUTES:
        return
    expected = str(
        getattr(request.state, "workspace_expected_tenant", "") or ""
    )
    if not expected or not _is_same_origin(request):
        return
    supplied = request.headers.get("x-second-shift-expected-tenant", "").strip()
    content_type = request.headers.get("content-type", "").lower()
    if not supplied and (
        content_type.startswith("application/x-www-form-urlencoded")
        or content_type.startswith("multipart/form-data")
    ):
        form = await request.form()
        supplied = str(form.get("_expected_tenant") or "").strip()
    if not constant_time_equals(supplied, expected):
        raise HTTPException(
            status_code=409,
            detail=(
                "the active workspace changed after this page loaded; reload "
                "the page and review the action before trying again"
            ),
        )


app = FastAPI(
    title="Second Shift Dashboard + REST API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    description="Local browser UI plus REST API for programmatic access.",
    # The installed maverick-dashboard release (see maverick_dashboard.__version__).
    version=_dashboard_version,
    # Global authentication dependency, applied to every route. It composes
    # proxy/OIDC/SAML/invite sessions and the static dashboard bearer, while
    # preserving same-origin loopback mode only when authentication is genuinely
    # off. `enforce_page_visibility` runs second so role-based page policy sees
    # the established principal.
    dependencies=[
        Depends(require_principal_in_request_context),
        Depends(enforce_expected_workspace_tenant),
        Depends(_page_visibility),
    ],
    lifespan=_lifespan,
)
app.include_router(api_router)
from .static_files import router as static_files_router  # noqa: E402

app.include_router(static_files_router)
from .agent_drift_api import router as agent_drift_router  # noqa: E402

app.include_router(agent_drift_router)
from .alerts_api import router as alerts_router  # noqa: E402
from .teams_bot import router as teams_router  # noqa: E402

app.include_router(alerts_router)
app.include_router(teams_router)
from .agent_watch_api import router as agent_watch_router  # noqa: E402
from .agent_watch_api import switch_view as _platform_switch_view  # noqa: E402

app.include_router(agent_watch_router)
from .directory_api import router as directory_router  # noqa: E402

app.include_router(directory_router)
from .connect_agent_api import router as connect_agent_router  # noqa: E402

app.include_router(connect_agent_router)
from .ekko_ops_api import router as ekko_ops_router  # noqa: E402

app.include_router(ekko_ops_router)
# The signed-in person's Ekko page and recorder key, and the recorder's own two
# calls (a device key is the only credential those accept).
from .ekko_handover_api import router as ekko_handover_router  # noqa: E402

app.include_router(ekko_handover_router)
from .ekko_page import router as ekko_page_router  # noqa: E402

app.include_router(ekko_page_router)


def _compress_enabled() -> bool:
    """``[dashboard] compress`` (default on), overridden by
    ``MAVERICK_DASHBOARD_COMPRESS``. Response compression for a self-hosted
    dashboard behind a bare uvicorn or a default ingress; turn it off
    when a proxy in front already compresses."""
    env = os.environ.get("MAVERICK_DASHBOARD_COMPRESS", "").strip().lower()
    if env:
        return env in {"1", "true", "yes", "on"}
    try:
        from maverick.config import load_config

        value = ((load_config() or {}).get("dashboard") or {}).get("compress")
    except Exception:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return True


# Versioned static assets get the long cache; then gzip, added after it and
# so outside it: it compresses every route's response including the static
# bundles. It is not the outermost layer. Everything added later wraps it
# (the size limit below, the function middlewares defined further down, the
# request memo and activity count), so a response one of those produces by
# itself (a 401/403 from bearer_auth, the IP-allowlist refusal, an extension
# preflight, a 413) is not compressed. Starlette's
# middleware skips text/event-stream and already-compressed media types.
# Level 6 (zlib's default) instead of Starlette's 9: on the rendered pages
# it halves the per-response CPU cost for a 1-3% larger body.
app.add_middleware(StaticCacheMiddleware, version_for=static_version)
if _compress_enabled():
    from starlette.middleware.gzip import GZipMiddleware

    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)
# Outside gzip and every route: refuse an over-size request before any route's
# parser (the multipart form parser spools uploads to disk) reads it. The
# function middlewares defined below wrap this one, so those that read a body
# themselves (the ``bound_*`` ones) do so first, each under its own cap.
from .request_size import RequestSizeLimitMiddleware  # noqa: E402

app.add_middleware(RequestSizeLimitMiddleware)
from .agent_control_plane_page import (  # noqa: E402
    create_agent_control_plane_page_router,
)

app.include_router(create_agent_control_plane_page_router(templates))
from .audit_page import create_audit_page_router  # noqa: E402

app.include_router(create_audit_page_router(templates))
from .models_api import agent_router as models_agent_router  # noqa: E402
from .models_api import router as models_router  # noqa: E402
from .models_page import create_models_page_router  # noqa: E402

app.include_router(models_router)
app.include_router(models_agent_router)
app.include_router(create_models_page_router(templates))
from .my_agents_page import create_my_agents_page_router  # noqa: E402

app.include_router(create_my_agents_page_router(templates))
from .agent_control_plane_api import router as agent_control_plane_router  # noqa: E402

app.include_router(agent_control_plane_router, prefix="/api/v1")
# Ekko Work Discovery: a human review/control surface only.  Endpoint
# collectors do not enter through HTTP; they write through the local core
# daemon's owner/device/tenant-scoped store.
from .ekko_routes import router as ekko_router  # noqa: E402

app.include_router(ekko_router)
# Built-in OIDC browser-login routes (/auth/login, /auth/callback, /auth/logout).
# Each route self-gates on maverick.oidc.login_enabled() and 404s when the login
# flow isn't fully configured, so including the router unconditionally is inert
# off by default. See maverick_dashboard.oidc_login.
app.include_router(oidc_login_router)
# The sign-in timer's three reads (/auth/session/status, /activity, /renew) and
# the shell's `page_session` global that tells each page when sign-in ends.
from .session_expiry import page_session as _page_session  # noqa: E402
from .session_expiry import router as session_expiry_router  # noqa: E402

app.include_router(session_expiry_router)
templates.env.globals["page_session"] = _page_session
# Self-authenticating external integrations (/api/v1/external/...): agents on
# other platforms, signed discovery sensors, and invited vendor respondents use
# route-specific credentials instead of a dashboard session. Individual route
# families self-gate on their own configuration. The prefix is
# self-authenticating (see _AUTH_EXEMPT rationale for /a2a/v1).
from .external_gateway import router as external_gateway_router  # noqa: E402

app.include_router(external_gateway_router)
from .copilot_studio_gate_api import router as copilot_studio_gate_router  # noqa: E402

app.include_router(copilot_studio_gate_router)
from .factory_page import create_factory_router  # noqa: E402

app.include_router(create_factory_router(templates))

_DOCS_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: https:; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "script-src 'self' 'nonce-{script_nonce}' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)

# {script_nonce} is filled per response by security_headers.
_DEFAULT_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'nonce-{script_nonce}'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)


_AUTH_EXEMPT = {
    "/healthz",
    "/livez",
    "/readyz",
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
    # The A2A task endpoint enforces its own shared/per-agent bearer and trust
    # plane. Requiring the unrelated dashboard bearer here would either block
    # valid A2A identities or pressure operators to reuse one credential across
    # two trust domains.
    "/a2a/v1",
    # /webhook/start authenticates with its own HMAC signature instead of
    # the dashboard bearer / same-origin checks (external senders have
    # neither), so it must bypass the centralized middleware.
    *SELF_AUTH_WEBHOOK_PATHS,
    *SELF_AUTH_SIGNIN_RECOVERY_PATHS,
    # The exact HMAC webhook paths are shared with the global dependency. A
    # future /webhook/* route is authenticated by default until explicitly
    # added to that reviewed set.
    # Built-in OIDC browser-login endpoints: they bootstrap a session and carry
    # their own flow-level security (state/PKCE/signed cookies). They must be
    # reachable by a browser that has no dashboard token yet; each self-gates on
    # login_enabled() and 404s when the login flow is off.
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/auth/error",
    "/auth/local-owner",
    "/auth/local-login",
    "/auth/owner-second-factor",
    # The stylesheet, brand images, fonts and share-page renderer the
    # signed-out pages (sign-in, invitation, public rights form, shared
    # result) load before any session exists. One reviewed set of exact files,
    # shared with the global dependency (auth.PUBLIC_STATIC_PATHS).
    *PUBLIC_STATIC_PATHS,
    # The LLM gateway authenticates every call with its OWN bearer inside
    # maverick.llm_gateway (same rationale as /a2a/v1): callers are foreign
    # agents that hold the gateway credential, never the dashboard bearer.
    # Self-gates on [llm_gateway] enable and 403s when off.
    "/gateway/v1/chat/completions",
    "/gateway/v1/messages",
    "/gateway/v1/otel",
    # The consent webhook authenticates every delivery with its OWN HMAC
    # signature inside maverick.consent_registry (external CMPs hold the
    # webhook secret, never the dashboard bearer). Self-gates on
    # [consent_registry] webhook_enable and 403s when off.
    "/consent/webhook",
}
_EXTERNAL_BODY_SLOTS = 32
_EXTERNAL_BODY_TIMEOUT_SECONDS = 10.0
_external_body_limiters: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_external_body_limiter_lock = threading.Lock()


def _external_body_limiter() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    with _external_body_limiter_lock:
        limiter = _external_body_limiters.get(loop)
        if limiter is None:
            limiter = asyncio.Semaphore(_EXTERNAL_BODY_SLOTS)
            _external_body_limiters[loop] = limiter
        return limiter
_EVIDENCE_GATEWAY_PREFIX = "/api/v1/security/assurance/gateway/"
# Owner passphrase and authenticator-code steps: their bodies hold both secrets, so a 422 names
# the field and never echoes the value.
_OWNER_SECRET_PREFIXES = (
    "/auth/company-signin-recovery/",
    "/auth/company-saml-recovery/",
    "/api/v1/settings/sign-in-migration/review",
    "/api/v1/settings/single-sign-on/activation-review",
)


async def _read_limited_request_body(
    request: Request,
    *,
    max_bytes: int,
    too_large_detail: str,
) -> bytes:
    """Read a request body with a hard size cap.

    ``Content-Length`` lets us reject obviously oversized requests before
    reading any body bytes.  For chunked or otherwise lengthless requests,
    stream incrementally and abort as soon as the cap is exceeded instead of
    using ``request.body()``, which buffers the entire body before returning.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if declared > max_bytes:
            raise HTTPException(status_code=413, detail=too_large_detail)

    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > max_bytes - len(body):
            raise HTTPException(status_code=413, detail=too_large_detail)
        body.extend(chunk)
    return bytes(body)


def _external_body_max(path: str) -> int:
    return 256 * 1024


@app.middleware("http")
async def bound_public_governance_body(request: Request, call_next):
    """Cap machine-facing API request bodies before authentication and model parsing."""

    path = route_path(request)
    if request.method not in {"POST", "PUT", "PATCH"} and not path.startswith("/api/v1/external/"):
        return await call_next(request)
    if path.startswith("/api/v1/external/"):
        maximum = _external_body_max(path)
        detail = "external request body too large"
    else:
        return await call_next(request)
    limiter = _external_body_limiter() if path.startswith("/api/v1/external/") else None
    acquired = False
    try:
        if limiter is not None:
            try:
                await asyncio.wait_for(limiter.acquire(), timeout=1.0)
            except TimeoutError:
                return JSONResponse({"detail": "external request capacity is busy"}, status_code=503)
            acquired = True
        reader = _read_limited_request_body(request, max_bytes=maximum, too_large_detail=detail)
        try:
            body = await asyncio.wait_for(reader, timeout=_EXTERNAL_BODY_TIMEOUT_SECONDS) if limiter else await reader
        except TimeoutError:
            if acquired:
                limiter.release()
            return JSONResponse({"detail": "external request body timed out"}, status_code=408)
    except HTTPException as exc:
        if acquired:
            limiter.release()
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    except BaseException:
        if acquired:
            limiter.release()
        raise

    delivered = False

    async def replay_receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    request._body = body  # noqa: SLF001 - bounded ASGI body replay
    request._receive = replay_receive  # noqa: SLF001 - bounded ASGI body replay
    try:
        return await call_next(request)
    finally:
        if acquired:
            limiter.release()


# Safe methods skip the CSRF check (browsers send Origin/Referer
# inconsistently on GETs from address bars and bookmarks).
_CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _is_same_origin(request: Request) -> bool:
    """Allow only same-origin browser submissions for mutating form POSTs.

    Fails closed when no Origin or Referer is present on a mutating
    request. The previous fail-open branch ("Non-browser/API clients
    commonly omit both headers") was a soft-CSRF: any tab on the same
    machine could fire a no-cors fetch with both headers stripped and
    have it accepted. Real API clients send Authorization headers and
    are exempted by the bearer-auth middleware before they reach here.
    """
    if request.method in _CSRF_SAFE_METHODS:
        return True
    expected = request.url.netloc
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.netloc == expected:
            return True
        return False
    return False


def _require_same_origin(request: Request) -> None:
    """Reject a cross-site mutating form POST (403). Shared CSRF guard inlined by
    ~20 form handlers."""
    if not _is_same_origin(request):
        raise HTTPException(
            status_code=403,
            detail="cross-site form post blocked — for your security, changes "
            "must be made from the Second Shift page itself. Reload the "
            "dashboard and try again.",
        )


def _is_loopback_client(host: str) -> bool:
    """True for in-process/loopback callers (safe to serve without a token)."""
    if not host:
        return False
    # Starlette's in-process TestClient reports host="testclient"; a real
    # network peer can never present that (request.client.host is the
    # socket peer, set by the server, not user-controllable).
    if host in ("localhost", "testclient"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_loopback_request_host(request: Request) -> bool:
    """True when the user-controlled Host header names a loopback host.

    No-token mode is intentionally limited to local dashboards.  Checking only
    the socket peer is not enough for browser requests: a DNS-rebinding page can
    connect to 127.0.0.1 while preserving an attacker-controlled Host/Origin
    pair, which would otherwise satisfy Host-derived same-origin checks.
    """
    host = (request.url.hostname or "").rstrip(".").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Standard headers a reverse proxy adds when forwarding a request.
_PROXY_FORWARD_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded")


def _is_proxied(request: Request) -> bool:
    """True if a reverse proxy forwarded this request.

    In no-token mode the dashboard trusts the loopback peer
    (``request.client.host``). A reverse proxy on the same host connects over
    loopback, so a deploy that fronts the app with a public proxy but forgets
    to set ``MAVERICK_DASHBOARD_TOKEN`` on the app process would serve the
    control surface unauthenticated to the internet — the loopback peer is the
    proxy, not the real remote client. Treat any standard forwarding header as
    proof a proxy is in front and fall through to the token requirement (fail
    closed). Reading these headers only ever makes auth STRICTER, so a forged
    header cannot grant access — at worst a direct caller locks itself out by
    sending one.
    """
    return any(request.headers.get(h) for h in _PROXY_FORWARD_HEADERS)


def _configured_oidc_bearer_present(request: Request) -> bool:
    """Whether this request explicitly presents a bearer to enabled OIDC.

    Such API credentials do not use ambient browser authority, so they do not
    need an Origin/Referer. The global auth dependency remains authoritative:
    it verifies the token (and rejects an invalid one) before any cookie/proxy
    identity can be selected.
    """
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        return False
    try:
        from . import auth as auth_boundary

        return auth_boundary.oidc_enabled()
    except Exception:
        return False


def _api_key_bearer_present(request: Request) -> bool:
    """Whether this request presents a personal / service-account API key.

    Like an OIDC bearer it is explicit, non-ambient authority: no Origin check
    applies, and the global auth dependency verifies it (and 401s a bad,
    expired, revoked or out-of-scope one) before any cookie identity could be
    selected. Cheap shape check only -- no store read here.
    """
    try:
        from . import auth as auth_boundary

        return bool(auth_boundary._api_key_bearer(request))
    except Exception:
        return False


@app.middleware("http")
async def bearer_auth(request: Request, call_next):
    expected = _dashboard_token() or None
    path = route_path(request)
    if (
        path in _AUTH_EXEMPT
        or path.startswith("/share/")
        or path.startswith("/scim/")
        or path.startswith("/form/")
        # DSAR response links are addressed by their unguessable token,
        # exactly like /form/ — the requester has no dashboard bearer.
        or path.startswith("/dsar/response/")
        # One-action mute links in notification messages: the signed link is
        # the credential and only quiets that one person's own notifications.
        or path.startswith("/unsubscribe/")
        or path.startswith("/saml/")
        or path.startswith("/auth/invite/")
        # External integrations authenticate inside their route family
        # using agent, signed-sensor, or vendor-invitation credentials. The
        # trailing slash keeps /api/v1/external-agents under dashboard auth.
        or path.startswith("/api/v1/external/")
        # Copilot Studio's threat-detection calls carry a Microsoft Entra token.
        or path.startswith("/copilot-studio/")
        # Public consent uses its own client and profile capabilities. Keep
        # the exact administration prefix under dashboard authentication.
        or path.startswith("/api/v1/public/consent/")
        # Public policy links resolve an opaque stable link and optionally
        # a private bearer. The admin policy-publication prefix remains
        # under normal dashboard authentication.
        or path.startswith("/api/v1/public/policies/")
        # Pairing bootstrap authenticates its own opaque, expiring device proof.
        # Browser approval and device administration remain under normal auth.
        or path.startswith("/api/v1/devices/pairing/")
        # The public rights-request form (pages + JSON). Anonymous by
        # design; gated, origin-checked and token-addressed in its router.
        or path.startswith("/rights/")
        or path.startswith("/api/v1/public/rights/")
        # Public website chat (its own publishable key, origin and visitor
        # session). The admin prefix /api/v1/public-chat stays authenticated.
        or path.startswith("/public/chat/v1/")
    ):
        # /share/<token> self-authenticates with its signed, revocable token
        # (verified in the route, which 404s an invalid/expired/revoked one) --
        # an external recipient has no dashboard bearer, like the webhook paths.
        # /auth/invite/<token> is the same shape: the invitee has no credential
        # yet; the single-use token IS the auth, verified (and same-origin-
        # gated on the consuming POST) in the route, which 404s when invites
        # are disabled.
        return await call_next(request)
    if not expected:
        # Any configured identity mechanism disables legacy loopback-as-admin,
        # even when the separate startup assertion ``dashboard.require_auth``
        # is unset. The global dependency verifies proxy, OIDC, SAML, or invite
        # identity and fails closed on unreadable auth configuration.
        # Resolve through the module so identity-policy changes made by a
        # deployment/test harness cannot leave this long-lived middleware with
        # a stale function binding.
        from . import auth as auth_boundary

        if not auth_boundary.auth_genuinely_off():
            explicit_oidc_bearer = (_configured_oidc_bearer_present(request)
                                    or _api_key_bearer_present(request))
            if (
                not explicit_oidc_bearer
                and not _is_same_origin(request)
                and _allowed_extension_origin(request) is None
            ):
                return JSONResponse(
                    {
                        "detail": "cross-site request blocked - for your security, "
                        "changes must be made from the Second Shift page "
                        "itself. Reload the dashboard and try again."
                    },
                    status_code=403,
                )
            return await call_next(request)
        # Client-bound / enterprise: loopback-trust (no-token) mode is DISABLED.
        # In a hosted/regulated deployment any process sharing the loopback
        # namespace (a sidecar, a co-located container, an SSRF pivot to
        # 127.0.0.1) must never become an unauthenticated admin — require a
        # token (or OIDC) explicitly.
        try:
            from maverick.client import client_binding_enforced

            if client_binding_enforced():
                _auth_metrics.record_auth_failure("client_binding")
                return JSONResponse(
                    {
                        "detail": "Sign-in is required on this deployment — an "
                        "administrator must configure dashboard "
                        "authentication for enterprise / client-binding "
                        "mode (set MAVERICK_DASHBOARD_TOKEN, or enable "
                        "OIDC)."
                    },
                    status_code=401,
                )
        except Exception:  # pragma: no cover - never break auth on a read error
            pass
        # A personal / service-account API key is an explicit credential the
        # local operator minted on this computer: let the global dependency
        # verify it (it fails closed), so a script can reach Second Shift from
        # another computer without a shared static token.
        if _api_key_bearer_present(request):
            return await call_next(request)
        # No token configured: serve loopback only. An operator who binds
        # --host 0.0.0.0 without setting a token must NOT silently expose
        # run history, spend, and the control surface unauthenticated to
        # the network. Set MAVERICK_DASHBOARD_TOKEN to allow remote access.
        client_host = request.client.host if request.client else ""
        if (
            _is_loopback_client(client_host)
            and _is_loopback_request_host(request)
            and not _is_proxied(request)
        ):
            # Loopback is served without a bearer, so a malicious page open in
            # the user's browser could otherwise drive mutating endpoints via an
            # ambient cross-site request (CSRF): cancel/resume goals, disable
            # safety tools, arm the killswitch, purge caches. Gate unsafe methods
            # behind the same-origin check centrally (the one /chat/send already
            # enforces per-route) so every current and future /api/v1 mutation is
            # covered. Token mode needs no such check — a cross-site page cannot
            # attach the Authorization header.
            # The bundled WebExtension is the one sanctioned cross-origin
            # caller: its Origin is chrome-extension://… and it is accepted
            # only behind the operator's explicit opt-in (see extension_cors).
            if not _is_same_origin(request) and _allowed_extension_origin(request) is None:
                script_without_origin = (
                    path.startswith("/api/")
                    and not request.headers.get("origin")
                    and not request.headers.get("referer")
                )
                return JSONResponse(
                    {
                        "detail": (
                            "Local API writes need an Origin header matching this Second Shift "
                            "address, or an API key created in Account > API keys and sent as "
                            "Authorization: Bearer <key>. See the REST API guide."
                            if script_without_origin else
                            "cross-site request blocked — for your security, changes must "
                            "be made from the Second Shift page itself. Reload the dashboard "
                            "and try again."
                        )
                    },
                    status_code=403,
                )
            return await call_next(request)
        # A VERIFIED invite-minted session is a real credential: accept it for
        # remote access in no-token mode (same-origin-gated like every other
        # cookie mode), so an invites-only deployment works over the network
        # without extra config. Anonymous remote requests still 401 below.
        try:
            from .invites import invites_enabled, local_session_principal

            if invites_enabled() and local_session_principal(request) is not None:
                if not _is_same_origin(request) and _allowed_extension_origin(request) is None:
                    return JSONResponse(
                        {
                            "detail": "cross-site request blocked — for your "
                            "security, changes must be made from the "
                            "Second Shift page itself. Reload the "
                            "dashboard and try again."
                        },
                        status_code=403,
                    )
                return await call_next(request)
        except Exception:  # pragma: no cover - invites must never open access
            pass
        _auth_metrics.record_auth_failure("remote_no_token")
        return JSONResponse(
            {
                "detail": "Remote access to this dashboard requires an access "
                "token — an administrator must configure one for "
                "non-loopback or proxied access (set "
                "MAVERICK_DASHBOARD_TOKEN)."
            },
            status_code=401,
        )
    auth = request.headers.get("authorization", "")
    header_token = auth[7:] if auth.startswith("Bearer ") else ""
    # ``?token=`` query auth was removed: it leaks the bearer through
    # browser history, Referer headers on outbound link clicks, uvicorn
    # access logs, and any logging proxy in front. Require the
    # ``Authorization: Bearer`` header.
    if header_token and hmac.compare_digest(header_token.encode(), expected.encode()):
        return await call_next(request)
    if auth:
        # A non-static bearer may be an OIDC token in a mixed deployment. Let
        # the global dependency verify it; malformed/invalid credentials never
        # fall back to proxy or cookie identity there.
        if (header_token.startswith("ssdev1_") or _configured_oidc_bearer_present(request)
                or _api_key_bearer_present(request)):
            return await call_next(request)
        _auth_metrics.record_auth_failure("bad_token")
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    if non_static_auth_configured():
        # The static operator token composes with proxy/OIDC/SAML/invite browser
        # identities. Ambient authority remains CSRF-gated; the dependency then
        # verifies the actual identity and rejects a missing/invalid session.
        if not _is_same_origin(request) and _allowed_extension_origin(request) is None:
            return JSONResponse(
                {
                    "detail": "cross-site request blocked - for your security, "
                    "changes must be made from the Second Shift page "
                    "itself. Reload the dashboard and try again."
                },
                status_code=403,
            )
        return await call_next(request)
    # The bad/missing-bearer case — the credential-stuffing signal an alert
    # rule watches (a flood here means someone is probing the token).
    _auth_metrics.record_auth_failure("bad_token")
    return JSONResponse({"detail": "unauthorized"}, status_code=401)


def _wants_html(request: Request) -> bool:
    """True when the client prefers HTML (browser nav) over JSON (API)."""
    accept = (request.headers.get("accept") or "").lower()
    if route_path(request).startswith(
        ("/api/", "/openapi", "/healthz", "/livez", "/readyz", "/metrics")
    ):
        return False
    # Browser navigations explicitly advertise text/html. Generic HTTP clients
    # commonly send only */* and must retain the machine-readable JSON error
    # contract even when they call a non-/api form compatibility route.
    return "text/html" in accept


def _not_found_page(request: Request):
    """The browser 404: a plain public page for dead share links, else the app's."""
    if route_path(request).startswith("/share/"):
        # A shared-result recipient has no account: an unknown, expired or
        # revoked link gets a plain public page (no detail), never the app shell.
        return templates.TemplateResponse(
            request, "share_unavailable.html", {}, status_code=404,
            headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"},
        )
    return templates.TemplateResponse(
        request,
        "404.html",
        {"path": request.url.path},
        status_code=404,
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Branded, actionable HTML for browser failures; JSON for API callers."""
    from . import browser_signin

    headers = exc.headers
    if exc.status_code == 404 and _wants_html(request):
        return _not_found_page(request)
    if exc.status_code == 401 and browser_signin.is_browser_navigation(request):
        # A browser navigating to a protected page with no valid session lands
        # on the sign-in flow when one is configured. Bearer, non-GET and API
        # requests keep the JSON 401.
        try:
            from maverick.oidc import login_enabled as _login_enabled

            login_on = _login_enabled()
        except Exception:  # pragma: no cover - never turn an auth error into a 500
            login_on = False
        if login_on:
            return RedirectResponse(browser_signin.sign_in_url(request), status_code=302)
    if _wants_html(request):
        status = int(exc.status_code)
        title, message = {
            400: ("Check this request",
                  "The submitted value could not be used. Review the fields and try again."),
            401: ("Sign in required", "Your sign-in has expired. Sign in again."),
            403: ("Permission required",
                  "Your current role cannot use this page or action. Ask an administrator for access."),
            409: ("Refresh before continuing",
                  "The record changed after this page loaded. Reload it to see the current state before retrying."),
            429: ("Too many requests", "This service is protecting itself from overload. Wait briefly, then retry."),
            503: ("Temporarily unavailable",
                  "A required service or control is unavailable. Your action was not confirmed; "
                  "retry after service is restored."),
        }.get(status, ("Request could not be completed",
                       "The action was stopped before it was confirmed. Return to the page and try again."))
        gate = ""
        reauthenticate = ""
        if status == 403 and isinstance(exc.detail, str):
            from .mfa_policy import MFA_MISSING_MESSAGE as _mfa_missing
            from .step_up import StepUpRequired as _StepUpRequired

            if isinstance(exc, _StepUpRequired):
                gate = "step_up"
                title = "Sign in again to continue"
                message = exc.detail
                reauthenticate = exc.reauthenticate
            elif exc.detail == _mfa_missing:
                gate = "step_up"
                title = "Sign in again with your authenticator"
                message = exc.detail
                from .step_up import reauthenticate_url

                reauthenticate = reauthenticate_url(request)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "status": status,
                "title": title,
                "message": message,
                "path": request.url.path,
                "gate": gate,
                "reauthenticate": reauthenticate,
                "feature": {},
                "action": {},
            },
            status_code=status,
            headers=headers,
        )
    body: dict = {"detail": exc.detail}
    reauthenticate = getattr(exc, "reauthenticate", "")
    if reauthenticate:
        body["reauthenticate"] = reauthenticate
    return JSONResponse(body, status_code=exc.status_code, headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """422 for browser nav becomes 400 with the branded error page."""
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "500.html",
            {"path": request.url.path},
            status_code=400,
        )
    if route_path(request) == "/api/v1/connection-setup" or route_path(request).startswith(
        "/api/v1/connection-setup/"
    ):
        # Pydantic may place submitted secrets in input, msg, ctx, or even loc
        # (for unsupported object keys). Rebuild from fixed field labels before
        # encoding: malformed binary input must remain a safe 422, not a 500.
        messages = {
            "confirm": "Review and confirm the account connection action.",
            "context": "Refresh Connections before continuing.",
            "provider": "Select a supported account provider.",
            "client_id": "Enter a valid application client ID.",
            "client_secret": "Enter a valid application client secret.",  # pragma: allowlist secret
            "expected_revision": "Refresh Connections before changing this connection.",
            "profile": "Select a supported connection profile.",
            "name": "Use a connection name with lowercase letters, numbers, hyphens or underscores.",
            "site_url": "Enter a valid workspace site address.",
            "state": "Start a new authorization from Connections.",
            "code": "Start a new authorization from Connections.",
            "return_profile": "Choose the supported account return mode.",
            "desktop_return": "Review the provider's registered desktop return address.",
        }
        errors = []
        for error in exc.errors()[:32]:
            loc = error.get("loc", ())
            field = loc[1] if isinstance(loc, (list, tuple)) and len(loc) == 2 and loc[0] == "body" else None
            field = field if isinstance(field, str) and field in messages else None
            errors.append({
                "type": "value_error",
                "loc": ["body", field] if field else ["body"],
                "msg": messages[field] if field else "Check the connection fields and remove unsupported fields.",
            })
        return JSONResponse({"detail": errors}, status_code=422, headers={"Cache-Control": "no-store"})
    # exc.errors() can embed the raw request body (bytes) in 'input' when the
    # client sent a wrong/garbage Content-Type; json.dumps can't serialize bytes,
    # so a 422 turned into an opaque 500. jsonable_encoder coerces bytes -> str.
    from fastapi.encoders import jsonable_encoder

    errors = jsonable_encoder(exc.errors())
    if route_path(request).startswith(_EVIDENCE_GATEWAY_PREFIX) or route_path(request).startswith(
        _OWNER_SECRET_PREFIXES
    ):
        for error in errors:
            if isinstance(error, dict) and "input" in error:
                error["input"] = "[redacted]"
    try:
        return JSONResponse({"detail": errors}, status_code=422)
    except ValueError:
        # The error echoes the rejected input. A lone surrogate in a JSON string
        # cannot be written as UTF-8 (UnicodeEncodeError) and a non-finite number
        # (NaN, Infinity) is not JSON at all: escape the first and name the
        # second as a string instead of answering 500.
        safe = json.loads(json.dumps({"detail": errors}), parse_constant=str)
        return Response(json.dumps(safe), status_code=422, media_type="application/json")


@app.exception_handler(OverflowError)
async def overflow_exception_handler(request: Request, exc: OverflowError):
    """An out-of-range integer path param (e.g. goal_id > 2**63-1) can't be a real
    row -- SQLite raises OverflowError binding it. Treat it as not-found rather
    than letting it fall through to a 500."""
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "404.html",
            {"path": request.url.path},
            status_code=404,
        )
    return JSONResponse({"detail": "not found"}, status_code=404)


from .rbac import RbacStoreError as _RbacStoreError  # noqa: E402


@app.exception_handler(_RbacStoreError)
async def rbac_store_exception_handler(request: Request, exc: _RbacStoreError):
    """Unreadable or missing role policy is a plain refusal, never a grant or 500."""
    from .rbac import ROSTER_RECOVERY, RosterMissingError, RosterRollbackError

    log.error("dashboard role policy is unavailable on %s: %s", request.url.path, exc)
    if isinstance(exc, RosterRollbackError):
        # The change was refused but could not be taken back: do not claim
        # that nothing changed.
        detail = ("The role change was refused by the activity log, but the role list could not be put back "
                  "and may now include it. Ask an administrator to check the role list.")
    else:
        detail = ("Access roles cannot be read, so nothing was changed and no access was granted. "
                  + (f"The role list is missing. {ROSTER_RECOVERY}"
                     if isinstance(exc, RosterMissingError)
                     else "Ask an administrator to restore or repair the role list."))
    if _wants_html(request):
        return templates.TemplateResponse(request, "error.html", {
            "status": 503, "title": "Access roles unavailable", "message": detail,
            "path": request.url.path, "gate": "", "reauthenticate": "", "feature": {},
        }, status_code=503)
    return JSONResponse({"detail": detail, "code": "access_roles_unavailable"}, status_code=503)


from maverick.world_model import WorldBackendUnreadable as _WorldBackendUnreadable  # noqa: E402


@app.exception_handler(_WorldBackendUnreadable)
async def world_backend_refused_handler(request: Request, exc: _WorldBackendUnreadable):
    """The records database was refused (Postgres was last used and the
    settings no longer choose it): a plain 503, never a generic 500. The
    details, which name files, stay in the server log."""
    log.error("records database refused on %s: %s", request.url.path, exc)
    detail = ("Second Shift will not open a local records database, because it last used "
              "its Postgres database and the settings no longer choose one. "
              "An administrator can find the fault by checking the readiness address (/readyz) and the server log.")
    if _wants_html(request):
        return templates.TemplateResponse(request, "error.html", {
            "status": 503, "title": "Records database unavailable", "message": detail,
            "path": request.url.path, "gate": "", "reauthenticate": "", "feature": {},
        }, status_code=503)
    return JSONResponse({"detail": detail, "code": "records_database_refused"}, status_code=503)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all so we never serve the default white "Internal Server Error"."""
    from datetime import datetime, timezone
    from secrets import token_hex

    reference = "ss-failure-" + token_hex(16)
    occurred_at = datetime.now(timezone.utc).isoformat()
    route = getattr(request.scope.get("route"), "path", "unmatched route")
    log.error("dashboard failure reference=%s time=%s action=%s route=%s",
              reference, occurred_at, request.method, route,
              exc_info=(type(exc), exc, exc.__traceback__))
    headers = {"Cache-Control": "private, no-store", "X-Second-Shift-Failure-Reference": reference}
    from maverick.service_status import READ_ONLY_REFUSAL, database_refusal, is_read_only_error

    # A write refused by a read-only database says what broke, that
    # saved work is safe and what to do, never the database error itself.
    # A database setup refusal names the fix in the server log.
    read_only = is_read_only_error(exc)
    database_error = database_refusal(exc)
    status = 503 if read_only or database_error else 500
    if _wants_html(request):
        try:
            return templates.TemplateResponse(
                request, "500.html", {"failure_reference": reference, "failure_time": occurred_at,
                                      "uncertain_mutation": request.method not in {"GET", "HEAD"},
                                      "read_only_error": read_only, "database_error": database_error},
                status_code=status, headers=headers,
            )
        except Exception:
            # Deliberately independent of the normal layout and its data reads.
            return HTMLResponse(
                '<!doctype html><html lang="en"><meta charset="utf-8"><title>Second Shift needs attention</title>'
                '<h1>Something went wrong</h1><p>Check the current state before repeating a change.</p>'
                f'<p>Support reference: {reference}</p><p>Time: {occurred_at}</p>'
                f'<a href="/">Back to home</a></html>',
                status_code=500, headers=headers,
            )
    detail = READ_ONLY_REFUSAL if read_only else database_error or (
        "The request could not be completed. Check its current state before retrying a change.")
    return JSONResponse({"detail": detail, "failure_reference": reference, "occurred_at": occurred_at},
                        status_code=status, headers=headers)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Apply baseline browser-security headers to every response.

    These are cheap, well-supported, and close a class of attacks
    (clickjacking, MIME sniffing, Referer leakage, cross-origin
    exfiltration) the dashboard had no defense against before.
    """
    # One script nonce per response, for the inline <script> tags the templates
    # render (csp_script_nonce, see _csp_nonce_context).
    script_nonce = secrets.token_urlsafe(16)
    request.state.csp_script_nonce = script_nonce
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    # "same-origin", NOT "no-referrer": under no-referrer the Fetch spec makes
    # browsers send "Origin: null" on same-origin form POST navigations, which
    # the CSRF guard (_is_same_origin) must reject — so every native form save
    # in the dashboard 403'd in a real browser ("cross-site request blocked")
    # while fetch()-based saves (mode "cors" keeps the real Origin) and tests
    # (explicit Origin header) still passed. same-origin keeps the privacy win
    # (no Referer leaks to external sites) and restores Origin/Referer on
    # first-party requests.
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Cross-Origin-Opener-Policy",
        "same-origin",
    )
    # Drop the ambient-capability attack surface. microphone=(self) because
    # the chat pages capture voice in-browser (getUserMedia); camera,
    # geolocation, and payment are never used, so deny them outright.
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), camera=(), payment=(), microphone=(self)",
    )
    # no-store on everything by default so authenticated HTML and sensitive
    # JSON aren't left in the browser's back/forward cache or a shared proxy
    # after logout. setdefault preserves the explicit caching the static-asset
    # and SSE routes already set (public max-age / no-cache).
    response.headers.setdefault("Cache-Control", "no-store")
    # HSTS only when the request actually arrived over TLS (directly or via a
    # terminating proxy) — never on plain-HTTP loopback dev, which HSTS would
    # otherwise pin to https and break.
    if (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
    ):
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    # Content-Security-Policy. Inline <script> tags carry this response's
    # nonce, so script-src admits no 'unsafe-inline' and an injected inline
    # script cannot run. The templates' first-party inline <style> and
    # style="" attributes still need 'unsafe-inline' in style-src (out of
    # scope for this change). The value still hardens the dashboard meaningfully:
    #   - default/connect/script/style 'self' → injected JS can't fetch()
    #     to an external exfil endpoint or pull a remote script
    #   - frame-ancestors 'none' → reinforces X-Frame-Options (clickjack)
    #   - form-action 'self' → an injected <form> can't POST off-origin
    #   - object-src 'none', base-uri 'none' → kill plugin + <base> tricks
    # This matters because the dashboard renders agent-produced text;
    # if any of it ever reaches an HTML sink, CSP is the backstop.
    path = route_path(request)
    if path == "/redoc":
        csp = _DOCS_CSP.format(script_nonce=script_nonce)
    else:
        csp = _DEFAULT_CSP.format(script_nonce=script_nonce)
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


# ----- browser-extension CORS gate (extensions/browser) -----
# The bundled WebExtension is a cross-origin caller: its popup/service-worker
# fetches arrive with an Origin of chrome-extension://<id> (moz-extension://
# <uuid> on Firefox). Browsers need CORS approval for it to read responses,
# and the no-token CSRF gate in bearer_auth would otherwise 403 its POSTs.
# This allowance is OPT-IN and fail-closed: until the operator sets
# `[dashboard] allow_extension = true` (or MAVERICK_DASHBOARD_ALLOW_EXTENSION=1)
# AND configures MAVERICK_DASHBOARD_TOKEN, no CORS header is ever emitted and
# extension origins stay blocked. Requiring a bearer token keeps extension
# support from turning no-token loopback mode into an ambient trust boundary for
# any installed browser extension. The allowance is scoped to extension origins
# only — a web origin (https://…) never matches, so the same-origin posture for
# ordinary sites is unchanged.
_EXTENSION_ORIGIN_RE = re.compile(r"^(?:chrome|moz)-extension://[a-zA-Z0-9-]+$")


def _extension_cors_enabled() -> bool:
    """Operator opt-in for the bundled WebExtension. Fail-closed default."""
    if os.environ.get("MAVERICK_DASHBOARD_ALLOW_EXTENSION") == "1":
        return True
    try:
        from maverick.config import load_config

        return bool(((load_config() or {}).get("dashboard") or {}).get("allow_extension"))
    except Exception:
        return False


def _allowed_extension_origin(request: Request) -> str | None:
    """The request's Origin, iff extension CORS is enabled and token-gated."""
    origin = request.headers.get("origin") or ""
    if (
        _dashboard_token()
        and _EXTENSION_ORIGIN_RE.match(origin)
        and _extension_cors_enabled()
    ):
        return origin
    return None


@app.middleware("http")
async def tenant_pinning(request: Request, call_next):
    """Reset any per-request tenant pin established by authentication.

    The actual pin is set inside ``require_principal`` after FastAPI has resolved
    the verified caller but before route handlers run. This outer middleware owns
    cleanup so the ContextVar token never leaks across requests/tasks.
    """
    try:
        return await call_next(request)
    finally:
        token = getattr(request.state, "tenant_pin_token", None)
        if token is not None:
            try:
                from maverick.paths import reset_tenant

                reset_tenant(token)
            except Exception:  # pragma: no cover
                pass


@app.get("/external-agents", response_class=HTMLResponse)
async def external_agents_page(
    request: Request, level: str = "", platform: str = "", add: str = "", connect: str = "",
) -> HTMLResponse:
    """Outside-agent console: one roster of agents found on other platforms,
    added here and connected, with the add form, access keys and the guided
    connect path. ``level`` and ``platform`` filter the roster; ``add`` is the
    platform record of a found agent whose details pre-fill the add form;
    ``connect`` is an added agent whose guided connect path opens."""
    from maverick import connect_guide, entra_directory, outside_roster, starter_rules
    from maverick import external_agents as xa

    enabled = xa.enabled()
    agents = xa.roster()
    claimed = frozenset(str(agent.get("external_ref") or "").casefold() for agent in agents) - {""}
    checks = await run_in_threadpool(_platform_checks_view, claimed) if enabled else None
    found = (checks or {}).get("not_enrolled") or []
    roster = outside_roster.build(agents, found, level=level, platform=platform)
    for row in roster["rows"]:
        row["gate"] = connect_guide.gate_for(row["platform_key"], str(row.get("external_ref") or ""))
    prefill = next((entry for entry in found if entry["external_ref"] == add), None)
    connect_agent = next((dict(a, gate=connect_guide.gate_for(a["platform"], str(a.get("external_ref") or "")))
                          for a in agents if a["id"] == connect), None)
    return templates.TemplateResponse(
        request,
        "external_agents.html",
        {
            "enabled": enabled,
            "external_agents_can_manage": enabled and has_permission(request, "admin"),
            "owner_search": enabled and has_permission(request, "admin") and entra_directory.enabled(),
            "status": xa.status(),
            "agents": agents,
            "roster": roster,
            "level_filter": level if level in outside_roster.LEVELS else "",
            "platform_filter": platform if platform in {p["key"] for p in roster["platforms"]} else "",
            "prefill": prefill,
            "connect_agent": connect_agent,
            "prefill_platform": outside_roster.CHECK_PLATFORMS.get(prefill["platform"], "") if prefill else "",
            "starters": starter_rules.STARTERS,
            "guides": connect_guide.all_guides(),
            "platforms": xa.PLATFORMS,
            "surfaces": xa.TOKEN_SURFACES,
            "outside_agent_tabs": None,
            "platform_checks": checks,
            "platform_checks_shown": enabled,
            "alert_delivery": await run_in_threadpool(_alert_delivery_view),
        },
    )


def _alert_delivery_view() -> dict | None:
    """How alerts are delivered, for the roster page. None when the settings
    cannot be read: the page says so instead of failing."""
    try:
        from maverick import ops_alert

        return ops_alert.delivery_status()
    except Exception:
        log.warning("alert delivery settings unavailable", exc_info=True)
        return None


def _platform_checks_view(claimed: frozenset[str]) -> dict | None:
    """What the platform checks last found, for the roster page. None when the
    record cannot be read: the page says so instead of failing.

    The list is as of each platform's last check, so an agent added here since
    then (its reference is in ``claimed``) is left out without waiting for the
    next one."""
    try:
        from maverick import agent_watch

        status = agent_watch.status()
        found = agent_watch.unenrolled()
        waiting = [entry for entry in found if entry["external_ref"].casefold() not in claimed]
        status["not_enrolled_count"] = max(0, status["not_enrolled_count"] - (len(found) - len(waiting)))
        return {"status": status, "not_enrolled": waiting}
    except Exception:
        log.warning("platform check record unavailable", exc_info=True)
        return None


def _agent_drift_view(agent_id: str) -> dict | None:
    """The agent's drift state for its page; None when the record cannot be read."""
    try:
        from maverick import agent_drift

        return agent_drift.detail(agent_id)
    except Exception:
        log.warning("agent drift record unavailable", exc_info=True)
        return None


def _agent_model_findings(agent_id: str) -> list | None:
    """Open drift findings on the models the agent uses; None when the register cannot be read."""
    try:
        from maverick import model_register

        return model_register.findings_for_agent(agent_id)
    except Exception:
        log.warning("model register unavailable", exc_info=True)
        return None


@app.get("/external-agents/{agent_id}", response_class=HTMLResponse)
async def external_agent_scorecard(request: Request, agent_id: str) -> HTMLResponse:
    """One external agent's scorecard: ceilings, spend vs budget, run
    history on the Operating Record, and governance state (containment,
    wall violations, credentials)."""
    from maverick import external_agents as xa

    from .external_agent_detail_service import detail_for

    detail = await run_in_threadpool(detail_for, request, agent_id)
    can_manage = xa.enabled() and has_permission(request, "admin")
    access = None
    return templates.TemplateResponse(
        request, "external_agent_detail.html",
        {"a": detail, "can_manage": can_manage, "access": access,
         "can_respond": has_permission(request, "respond"),
         "drift": await run_in_threadpool(_agent_drift_view, agent_id),
         "model_findings": await run_in_threadpool(_agent_model_findings, agent_id),
         "platform_switch": await run_in_threadpool(_platform_switch_view, agent_id)},
        headers={"Cache-Control": "private, no-store"}
    )


def _approval_source(provenance: str | None) -> str | None:
    """Label trusted governance/Art-14 approvals, else ``None``.

    Approval ``detail`` is free-form operator context and may include
    model-, user-, or remote-server-controlled text. Only the explicit
    trusted ``provenance`` field may drive source labels in the decision UI.
    """
    if provenance == "governance":
        return "Required human oversight (EU AI Act)"
    if provenance == "external_agents":
        return "Outside agent"
    if provenance == "factory_release":
        return "Agent ready to release"
    if provenance == "harness_refine":
        # A change to the standing instructions every agent follows. An
        # approver must see that at a glance, not read it as an ordinary task
        # approval. People suggest these (Learned page or CLI), so the label
        # names the change, not an agent asking for itself.
        return "Change to the instructions agents follow"
    if provenance == "assessment":
        return "Assessment review"
    if provenance == "plan":
        # [autonomy] confirm_plan: the task's first outside action waits for
        # a person to check the whole plan (maverick.plan_review).
        return "Plan to check before the task acts"
    if provenance == "goal_risk":
        # A task held before it starts because its wording looks risky.
        return "Task waiting to start"
    if provenance == "ifc":
        return "Sensitive data about to leave Second Shift"
    return None


def _approval_viewer_context(request: Request | None, approvals: list) -> dict:
    """Who is looking at the queue, so a card can say "your own request", and
    -- when the enforced rules keep that person from approving it -- why."""
    if request is None:
        return {"approval_viewer": "", "own_request_notes": {}}
    from .api import _supervisor
    from .approval_decisions import own_request_note

    viewer = _supervisor(request)
    world = _world()
    notes = {}
    for approval in approvals:
        note = own_request_note(world, approval, viewer)
        if note:
            notes[approval.id] = note
    return {"approval_viewer": viewer, "own_request_notes": notes}


def _approval_progress(approvals: list, request: Request) -> dict:
    """Each pending card's approval progress, in the words the card shows.

    The same facts ``GET /api/v1/approvals/{id}/state`` returns, rendered with
    the page instead of fetched once per card after load. Callers pass only
    the approvals the viewer may open (the page routes filter with
    ``can_read_approval``, the state API's content check); the state API's
    approve floor applies here too.
    """
    if not has_permission(request, "approve"):
        return {}
    from maverick.safety.dual_control import allow_self_approval

    from .api import _supervisor
    from .approval_decisions import own_request_note

    who = _supervisor(request)
    world = _world()
    progress = {}
    for approval in approvals:
        try:
            state = world.approval_state(approval.id)
        except Exception:  # noqa: BLE001 - the card keeps its server-side checks
            continue
        if not state or state.get("status") != "pending":
            continue
        required = int(state.get("approvals_required") or 1)
        words = ["One approval is needed." if required <= 1
                 else f"{state.get('approved_count', 0)} of {required} required approvals received."]
        from maverick.safety.dual_control import includes_person

        recorded = includes_person(state.get("approvers") or [], who)
        if recorded:
            words.append("Your approval is recorded.")
        elif state.get("requested_by") and state.get("requested_by") == who:
            # The words follow what is enforced: one approver may be the person
            # who asked; under two-person approval their vote may not count.
            # When another approver must decide, the card already says why.
            if own_request_note(world, approval, who):
                pass
            elif required > 1 and not allow_self_approval():
                words.append("You asked for this, so other people must approve it.")
            elif required <= 1:
                words.append("You asked for this, so approving it approves your own request.")
            else:
                words.append("You asked for this; your approval counts as one of them.")
        progress[approval.id] = {"text": " ".join(words), "recorded": recorded}
    return progress


def _approval_queue_context(approvals: list, request: Request | None = None) -> dict:
    """Build the exact-operation review context shared by approval surfaces."""

    from maverick.approval_cards import ApprovalCardError, decode_approval_detail
    from maverick.safety.secret_detector import redact

    def safe(value: object, *, fallback: str = "") -> str:
        try:
            text, _matches = redact(" ".join(str(value or "").split()))
            return text[:2000]
        except Exception:
            return fallback

    sources = {approval.id: _approval_source(approval.provenance) for approval in approvals}
    cards = {}
    card_statuses = {}
    approval_details = {}
    approval_actions = {}
    approval_scopes = {}
    assessment_ids = {}
    for approval in approvals:
        approval_actions[approval.id] = safe(
            approval.action, fallback="reviewed operation",
        )
        approval_scopes[approval.id] = safe(
            approval.scope, fallback="reviewed target",
        )
        # Assessment UI enhancement is selected from explicit, app-owned
        # provenance. Free-form detail, target labels, and model output must not
        # be able to opt another approval into a DOM rewrite by containing an
        # ``assessment:...`` substring.
        if approval.provenance == "assessment":
            assessment_match = re.search(
                r"\[assessment:([A-Za-z0-9._-]{1,128})\]\s*$",
                str(approval.detail or ""),
            )
            if assessment_match:
                assessment_ids[approval.id] = assessment_match.group(1)
        try:
            card = decode_approval_detail(approval.detail)
        except ApprovalCardError:
            card = None
            card_statuses[approval.id] = "invalid"
            approval_details[approval.id] = (
                "Structured approval details failed their integrity check."
            )
        else:
            cards[approval.id] = card
            if card is not None and approval.provenance == "factory_release":
                approval_actions[approval.id] = card["summary"]  # a plain title, not the machine-readable action
            approval_details[approval.id] = (
                card["summary"] if card is not None else safe(approval.detail)
            )
            card_statuses[approval.id] = (
                "expired"
                if card is not None and time.time() >= card["expires_at"]
                else ("current" if card is not None else "legacy")
            )
    return {
        "sources": sources,
        "cards": cards,
        "card_statuses": card_statuses,
        "approval_details": approval_details,
        "approval_actions": approval_actions,
        "approval_scopes": approval_scopes,
        "assessment_ids": assessment_ids,
        "approval_progress": _approval_progress(approvals, request) if request is not None else {},
        **_approval_viewer_context(request, approvals),
    }


@app.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request) -> HTMLResponse:
    """Actions waiting for a person to approve or reject.

    An outside agent's high-risk action waits here, and so does a request for
    an access key when step-up approval is on. Gated on ``approve``, the same
    as the API the page calls.
    """
    require_permission(request, "approve")
    from .content_access import can_read_approval

    world = _world()
    pending = list(world.pending_approvals())
    approvals = [row for row in pending if can_read_approval(request, row, world)]
    return templates.TemplateResponse(
        request,
        "approvals.html",
        {
            "approvals": approvals,
            "private_count": len(pending) - len(approvals),
            **_approval_queue_context(approvals, request),
        },
        headers={"Cache-Control": "private, no-store"},
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    """What needs the signed-in person today (see ``home_page``)."""
    from .home_page import build

    return templates.TemplateResponse(
        request, "home.html", {"home": await run_in_threadpool(build, request)},
        headers={"Cache-Control": "private, no-store"},
    )


@app.get("/livez")
async def livez() -> dict:
    """Process is alive (TCP-accept liveness only)."""
    return {"status": "ok"}


@app.get("/healthz")
async def healthz() -> JSONResponse:
    """Deep health: the database answers."""
    def _database_answers() -> bool:
        try:
            _world().ping()
            return True
        except Exception:
            return False

    ok = await run_in_threadpool(_database_answers)
    return JSONResponse({"status": "ok" if ok else "degraded"}, status_code=200 if ok else 503,
                        headers={"Cache-Control": "no-store"})


@app.get("/readyz")
async def readyz() -> JSONResponse:
    """Ready to serve traffic: the same check as /healthz."""
    return await healthz()


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Second Shift web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if not _is_loopback_host(args.host) and not _dashboard_token():
        raise SystemExit(
            "Refusing to bind to a non-loopback host without MAVERICK_DASHBOARD_TOKEN set."
        )
    try:
        from maverick.logging_config import configure_logging

        configure_logging()
    except Exception:  # pragma: no cover - logging setup never blocks startup
        pass
    import uvicorn

    try:
        from maverick.proxy_auth import uvicorn_launch_kwargs

        proxy_kwargs = uvicorn_launch_kwargs()
    except Exception:  # pragma: no cover - never block startup on a config read
        proxy_kwargs = {}
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", **proxy_kwargs)


# This must remain after every route declaration so lazy included-router
# contexts and request-scope route objects receive the same final identity.
_stabilize_effective_route_names(app)

# Every middleware and handler below the memo shares one per-request memo for
# configuration-derived authorization predicates. Outside it (added last), the
# activity count lets start-up work wait for a quiet moment.
from ._request_memo import RequestMemoMiddleware  # noqa: E402

app.add_middleware(RequestMemoMiddleware)


if __name__ == "__main__":
    main()
