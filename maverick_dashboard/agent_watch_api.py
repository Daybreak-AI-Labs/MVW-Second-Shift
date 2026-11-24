"""Operator API for platform checks.

Read what the agents' home platforms last reported (each platform's last
result and the agents found there that are not enrolled), or run a check now.
Reading needs the view permission. Running a check needs admin: it signs in to
other platforms with this installation's credentials.

It does not change any setting, enroll anything, or act on what a check finds;
a changed configuration reaches an operator through the drift endpoints.

One write exists, for an administrator only: switching an enrolled agent off
(or back on) on its own platform, where the platform documents a way and the
settings allow it. The caller names the agent and nothing else; the platform id
comes from the agent's own record.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

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


class SwitchIn(BaseModel):
    """Which way, and that the person confirmed. Nothing else is accepted: no
    address, no platform and no platform id."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["off", "on"]
    confirmed: Literal[True]


def switch_view(agent_id: str) -> dict | None:
    """What can be done to switch one agent off on its platform, for its page;
    ``None`` when that cannot be worked out (the page then says nothing about it)."""
    try:
        from maverick import agent_watch_switch

        return agent_watch_switch.offer(agent_id)
    except Exception:
        return None


@router.get("/external-agents/{agent_id}/platform-switch")
async def platform_switch_offer(request: Request, agent_id: str) -> dict:
    """What can be done to switch this agent off on its own platform (view)."""
    require_permission(request, "view")
    _require_governance_on()
    from maverick import agent_watch_switch

    return await _switching(lambda: agent_watch_switch.offer(agent_id))


@router.post("/external-agents/{agent_id}/platform-switch")
async def platform_switch(request: Request, agent_id: str, body: SwitchIn) -> dict:
    """Switch the agent off, or back on, on its own platform (admin)."""
    require_permission(request, "admin")
    _require_governance_on()
    from maverick import agent_watch_switch

    actor = caller_principal(request) or "admin"
    return await _switching(lambda: agent_watch_switch.switch(agent_id, action=body.action, actor=actor))


async def _switching(work):
    """Run one switch call off the event loop, turning its refusals into plain HTTP answers."""
    from maverick import agent_watch_switch
    from maverick.agent_watch import AgentWatchStoreError
    from maverick.audit.errors import AuditRefused

    try:
        return await run_in_threadpool(work)
    except agent_watch_switch.SwitchRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    except agent_watch_switch.SwitchFailed as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except AgentWatchStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AuditRefused as exc:
        raise HTTPException(
            status_code=503,
            detail="The audit log refused this request, so nothing was sent and nothing was changed.") from exc
