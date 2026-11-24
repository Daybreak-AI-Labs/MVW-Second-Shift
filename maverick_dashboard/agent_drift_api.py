"""Operator API for outside-agent drift.

Read an agent's drift state, approve its baseline, acknowledge a finding, or
run a check now. Reading needs the view permission, acknowledging and checking
need operate, and approving a baseline needs admin: the baseline is what every
later comparison is judged against.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

router = APIRouter(prefix="/api/v1")


class BaselineIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_days: int | None = Field(default=None, ge=1, le=30)
    force: bool = False


class AcknowledgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: str = Field(min_length=1, max_length=200)


def _require_governance_on() -> None:
    from maverick import external_agents

    if not external_agents.enabled():
        raise HTTPException(status_code=404, detail="Outside-agent governance is turned off.")


async def _call(work, *, missing: int = 404):
    """Run one drift call off the event loop, turning its refusals into plain HTTP answers."""
    from maverick.agent_drift import AgentDriftError, AgentDriftStoreError

    try:
        return await run_in_threadpool(work)
    except AgentDriftStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AgentDriftError as exc:
        raise HTTPException(status_code=missing, detail=str(exc)) from exc


@router.get("/agent-drift")
async def drift_roster(request: Request) -> dict:
    """Every enrolled agent's drift state."""
    require_permission(request, "view")
    _require_governance_on()
    from maverick import agent_drift

    return {"enabled": agent_drift.enabled(), "agents": await _call(agent_drift.roster_view)}


@router.get("/external-agents/{agent_id}/drift")
async def drift_detail(request: Request, agent_id: str) -> dict:
    """One agent's baseline, recent activity and findings."""
    require_permission(request, "view")
    _require_governance_on()
    from maverick import agent_drift

    return await _call(lambda: agent_drift.detail(agent_id))


@router.post("/external-agents/{agent_id}/drift/baseline")
async def drift_approve_baseline(request: Request, agent_id: str, body: BaselineIn) -> dict:
    """Approve the agent's recent activity as its baseline (admin)."""
    require_permission(request, "admin")
    _require_governance_on()
    from maverick import agent_drift

    actor = caller_principal(request) or "admin"
    # 409: the agent exists but its record is too thin to approve without force.
    return await _call(
        lambda: agent_drift.approve_baseline(agent_id, actor=actor, window_days=body.window_days, force=body.force),
        missing=409,
    )


@router.post("/external-agents/{agent_id}/drift/acknowledge")
async def drift_acknowledge(request: Request, agent_id: str, body: AcknowledgeIn) -> dict:
    """Acknowledge one open finding (operate)."""
    require_permission(request, "operate")
    _require_governance_on()
    from maverick import agent_drift

    actor = caller_principal(request) or "operator"
    return await _call(lambda: agent_drift.acknowledge(agent_id, body.finding, actor=actor))


@router.post("/external-agents/{agent_id}/drift/check")
async def drift_check(request: Request, agent_id: str) -> dict:
    """Compare the agent with its baseline now and report anything new (operate)."""
    require_permission(request, "operate")
    _require_governance_on()
    from maverick import agent_drift

    return await _call(lambda: agent_drift.check(agent_id))
