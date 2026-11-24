"""Administrator API for alert delivery.

Read how alerts are set up, or send a test message to every alert channel now.
Reading needs the view permission. Sending a test needs admin: it posts to the
team's channel and mailbox.

Neither answer holds a webhook address or a password. A webhook address is
reported only as set or not set; the email address alerts go to is shown. This
module does not change any setting: channels are chosen in the configuration.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter(prefix="/api/v1")

_NO_CHANNEL = ("No alert channel is set up. Name teams or email under [alerts] backends, "
               "then add that channel's settings.")
_UNREADABLE = "The alert settings could not be read."


def _summary(results: dict[str, str], *, enabled: bool) -> str:
    """One plain sentence about a finished test, for the person who ran it."""
    reached = [name for name, result in results.items() if result == "sent"]
    missed = [name for name in results if name not in reached]
    if not results:
        return _NO_CHANNEL
    if not reached:
        return "The test did not reach any alert channel."
    text = f"The test reached {' and '.join(reached)}"
    text += f" but not {' or '.join(missed)}." if missed else "."
    if not enabled:
        text += " Alerts are turned off, so nothing else is sent until they are turned on."
    return text


@router.get("/alerts")
async def alert_delivery(request: Request) -> dict:
    """Whether alerts are on, and each channel they go to with whether it is ready."""
    require_permission(request, "view")
    from maverick import ops_alert

    try:
        return await run_in_threadpool(ops_alert.delivery_status)
    except Exception as exc:  # noqa: BLE001 -- a settings problem is an answer, not a crash
        raise HTTPException(status_code=503, detail=_UNREADABLE) from exc


@router.post("/alerts/test")
async def alert_test(request: Request) -> dict:
    """Send a test message to every alert channel now and say what happened (admin)."""
    require_permission(request, "admin")
    from maverick import ops_alert

    results = await run_in_threadpool(ops_alert.send_test)
    enabled = await run_in_threadpool(ops_alert.alerts_enabled)
    return {
        "enabled": enabled,
        "sent": "sent" in results.values(),
        "results": results,
        "message": _summary(results, enabled=enabled),
    }
