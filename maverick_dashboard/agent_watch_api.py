"""Operator API for platform checks.

Read what the agents' home platforms last reported (each platform's last
result and the agents found there that are not enrolled), or run a check now.
Reading needs the view permission. Running a check needs admin: it signs in to
other platforms with this installation's credentials.

It does not change any setting, enroll anything, or act on what a check finds;
a changed configuration reaches an operator through the drift endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter(prefix="/api/v1")


def _require_governance_on() -> None:
    from maverick import external_agents

    if not external_agents.enabled():
        raise HTTPException(status_code=404, detail="Outside-agent governance is turned off.")


async def _call(work):
    """Run one platform-check call off the event loop, turning an unreadable record into a plain HTTP answer."""
    from maverick.agent_watch import AgentWatchStoreError

    try:
        return await run_in_threadpool(work)
    except AgentWatchStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _overview() -> dict:
    from maverick import agent_watch

    return {**agent_watch.status(), "not_enrolled": agent_watch.unenrolled()}


@router.get("/agent-watch")
async def watch_status(request: Request) -> dict:
    """Platform checks: each platform's last result, and the agents found that are not enrolled."""
    require_permission(request, "view")
    _require_governance_on()
    return await _call(_overview)


@router.post("/agent-watch/sync")
async def watch_sync(request: Request) -> dict:
    """Ask every configured platform for its agents now and return the summary (admin)."""
    require_permission(request, "admin")
    _require_governance_on()
    from maverick import agent_watch

    return await _call(agent_watch.sync)
