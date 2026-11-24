"""When the browser's sign-in ends, and staying signed in (WCAG 2.2.1).

Pages carry the signed session's end time so ``second-shift-session.js`` can
warn before it ends and offer to stay signed in. Sign-in here is always the
company's (OpenID Connect): a session keeps its original ceiling and the
installation's current, shorter limits, activity can extend only the
inactivity deadline, and "Stay signed in" returns to the company provider when
the absolute sign-in is ending. There is no local passphrase sign-in, so
nothing here mints a replacement session.

This module only reads the caller's own session and records activity on it; it
does not decide who may see a page.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from .auth import require_permission

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}
_ENDED = "Your sign-in has ended. Sign in again to continue."


def _payload(request: Request) -> dict | None:
    """The verified session cookie, or ``None`` (no cookie, wrong secret, unreadable settings)."""
    from maverick.web_session import verify_session

    from .oidc_login import SESSION_COOKIE

    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        from maverick.oidc import load_oidc_config

        secret = load_oidc_config().session_secret
        payload = verify_session(raw, secret) if secret else None
        return payload if isinstance(payload, dict) else None
    except Exception:  # an unreadable sign-in configuration shows no timer
        return None


def _ends(payload: dict) -> int | None:
    """When this session ends (epoch seconds), or ``None`` when it already has."""
    from . import session_registry
    from .session_policy import company_ttl, idle_minutes
    from .session_revocation import is_revoked

    value = payload.get("exp")
    if not isinstance(value, (int, float)) or is_revoked(payload.get("sub", ""), payload.get("iat")):
        return None
    try:
        sid = payload.get("sid")
        if sid:
            row = session_registry.current(sid, principal=f"user:{payload.get('sub')}")
            if row is None:
                return None
            value = min(value, row.effective_end)
        elif idle_minutes():
            return None
        else:
            value = min(value, float(payload["iat"]) + company_ttl(12 * 3600))
        return int(value) if value > time.time() else None
    except (KeyError, TypeError, ValueError, OSError):
        return None
    except session_registry.SessionStoreError:
        return None


def sign_in_path() -> str:
    """Where this installation signs people in (``return_to`` is added by the page)."""
    return "/auth/login"


def page_session(request: Request) -> dict | None:
    """For the page shell: the session's end, the server clock and how to keep it."""
    found = _payload(request)
    ends = _ends(found) if found else None
    if ends is None:
        return None
    from .session_policy import idle_minutes

    return {"expires_at": ends, "now": int(time.time()), "idle_minutes": idle_minutes(),
            "renew": "sign-in", "sign_in": sign_in_path()}


@router.get("/auth/session/status")
def session_status(request: Request) -> JSONResponse:
    """The current end time (another tab may have kept the session going)."""
    require_permission(request, "view")
    found = page_session(request)
    if found is None:
        return JSONResponse({"signed_in": False}, headers=_HEADERS)
    from .session_policy import idle_minutes

    return JSONResponse({"signed_in": True, "expires_at": found["expires_at"], "now": found["now"],
                         "renew": found["renew"], "idle_minutes": idle_minutes()}, headers=_HEADERS)


@router.post("/auth/session/activity")
def record_activity(request: Request) -> JSONResponse:
    """Keep this active signed browser session current; never renew an ended one."""
    from . import session_registry
    from .app import _require_same_origin

    require_permission(request, "view")
    _require_same_origin(request)
    found = _payload(request)
    if found is None or _ends(found) is None or not found.get("sid"):
        raise HTTPException(401, _ENDED)
    client = getattr(request, "client", None)
    session_registry.touch(found["sid"], activity=True,
                           ip=str(getattr(client, "host", "") or ""),
                           user_agent=request.headers.get("user-agent", ""))
    ends = _ends(found)
    if ends is None:
        raise HTTPException(401, _ENDED)
    return JSONResponse({"expires_at": ends, "now": int(time.time())}, headers=_HEADERS)


@router.post("/auth/session/renew")
def renew_session(request: Request) -> JSONResponse:
    """A company sign-in cannot be renewed here: say where to sign in again."""
    from .app import _require_same_origin

    require_permission(request, "view")
    _require_same_origin(request)
    found = _payload(request)
    if found is None or _ends(found) is None:
        raise HTTPException(401, _ENDED)
    return JSONResponse({"renew": "sign-in", "sign_in": sign_in_path()}, status_code=409, headers=_HEADERS)
