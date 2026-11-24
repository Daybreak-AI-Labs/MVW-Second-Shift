"""The Ekko page: one person's own consent, recorder and suggestions.

Shows the signed-in person what Ekko records and never records, then lets
them enroll one of their own computers, create the key its recorder needs,
start, pause, resume and stop recording, look for repeated work, and erase
what was recorded or withdraw their consent. Gated on ``operate``, the same as
every call the page makes.

The page only shows and sends. Each rule (who may enroll, which apps are
allowed, whether recording may start) is checked by the server routes it
calls. It has no view across people: every value comes from a store scoped to
the person who is signed in, and a device name only selects one of their own
devices.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from . import auth
from . import ekko_routes as ekko
from .ekko_handover_api import recorder_status

PAGE_PATH = "/ekko"
#: How long an enrollment may last; the same choices the enroll call accepts.
ENROLLMENT_DAYS = (7, 14, 30, 60, 90)

router = APIRouter()


def _sessions(request: Request, device_id: str) -> list[dict]:
    store = ekko._store(request, device_id)
    if not store.path.exists():
        return []
    return [ekko._public_session(session) for session in store.list_sessions(limit=20)]


def _recorder(request: Request, device_id: str) -> dict:
    """The recorder's state for the page. A key record that cannot be read is
    shown as such, with the way to clear it, instead of failing the page."""
    try:
        return recorder_status(request, device_id)
    except HTTPException as refused:
        if refused.status_code != 503:
            raise
        return {"has_key": True, "unreadable": True, "created_at": None, "last_heard_at": None, "heard_recently": False}


def _device_names(request: Request, current: str) -> list[str]:
    """This person's other devices that have a recorder key."""
    from maverick import ekko_device_keys as keys
    from maverick.paths import current_tenant_id

    try:
        names = keys.device_names(ekko._owner(request), tenant=current_tenant_id())
    except Exception:
        return []  # a convenience list; the page works without it
    return [name for name in names if name != current]


@router.get(PAGE_PATH, response_class=HTMLResponse)
def ekko_page(
    request: Request,
    device: str = Query(ekko._DEFAULT_DEVICE, min_length=1, max_length=64),
) -> HTMLResponse:
    """The signed-in person's own Ekko page for one of their devices."""
    from .app import templates

    auth.require_permission(request, "operate")
    status = ekko._status_data(request, device)
    session = status["session"] or {}
    return templates.TemplateResponse(
        request,
        "ekko.html",
        {
            "ekko": status,
            "recorder": _recorder(request, device),
            "sessions": _sessions(request, device),
            "other_devices": _device_names(request, status["device_id"]),
            "session_state": session.get("state", "none"),
            "enrolled": bool((status["enrollment"] or {}).get("active")),
            "day_choices": ENROLLMENT_DAYS,
            "server_address": str(request.base_url).rstrip("/"),
        },
        headers={"Cache-Control": "private, no-store"},
    )


__all__ = [
    "PAGE_PATH",
    "router",
]
