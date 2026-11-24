"""The status the guided "connect an agent" path polls.

``GET /api/v1/external-agents/{id}/connection`` answers whether the agent has
called Second Shift yet. It needs the view permission and says nothing beyond
the agent's level, when it was last heard from and what that call was.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter(prefix="/api/v1")


@router.get("/external-agents/{agent_id}/connection")
async def connection_status(request: Request, agent_id: str, response: Response) -> dict:
    """``{id, level, last_heard_at, received}`` for one added agent."""
    require_permission(request, "view")
    from maverick import external_agents, outside_roster

    if not external_agents.enabled():
        raise HTTPException(status_code=404, detail="Outside-agent governance is turned off.")
    response.headers["Cache-Control"] = "private, no-store"
    try:
        found = await run_in_threadpool(outside_roster.connection, agent_id)
    except external_agents.ExternalAgentsError as exc:
        raise HTTPException(status_code=503, detail="The list of added agents cannot be read.") from exc
    if found is None:
        raise HTTPException(status_code=404, detail="That agent has not been added.")
    return found
