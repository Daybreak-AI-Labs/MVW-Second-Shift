"""Read-only Microsoft 365 Copilot summaries from the caller's workspace."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from maverick import agent_drift, agent_watch, external_agents
from maverick.safety.secret_detector import redact

from ._shared import _world
from .auth import require_page_permission, require_permission

PREFIX = "/api/v1/m365-copilot"
READ_SCOPE = "SecondShift.Copilot.Read"
_ENTRA_TOKEN_STORE = "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b"
_TENANT = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
_LIMIT = 50
_PRIVATE = {"Cache-Control": "private, no-store"}


def has_copilot_scope(principal) -> bool:
    scopes = principal.claims.get("scp")
    return isinstance(scopes, str) and READ_SCOPE in scopes.split()


def _require_delegated_entra(request: Request, response: Response) -> None:
    principal = getattr(request.state, "principal", None)
    claims = principal.claims if principal is not None else {}
    tenant, oid = claims.get("tid"), claims.get("oid")
    if (
        not request.headers.get("Authorization", "").startswith("Bearer ")
        or principal is None or claims.get("ver") != "2.0"
        or not isinstance(tenant, str) or not _TENANT.fullmatch(tenant)
        or not isinstance(oid, str) or not _TENANT.fullmatch(oid)
        or principal.issuer != f"https://login.microsoftonline.com/{tenant}/v2.0"
        or claims.get("azp") != _ENTRA_TOKEN_STORE or not has_copilot_scope(principal)
    ):
        raise HTTPException(401, "Sign in through Microsoft 365 Copilot to use these summaries.",
                            headers={**_PRIVATE, "WWW-Authenticate": "Bearer"})
    response.headers.update(_PRIVATE)


router = APIRouter(prefix=PREFIX, dependencies=[Depends(_require_delegated_entra)], tags=["Microsoft 365 Copilot"])


def _unavailable() -> HTTPException:
    return HTTPException(503, "The saved information could not be read. Try again or open Second Shift.", headers=_PRIVATE)


def _text(value: object) -> str:
    clean, _ = redact(" ".join(str(value or "").split()))
    return clean[:500]


def _at(value: float | None) -> str | None:
    return datetime.fromtimestamp(value, tz=UTC).isoformat() if value is not None else None


def _page(key: str, rows: list[dict]) -> dict:
    return {key: rows[:_LIMIT], "more": len(rows) > _LIMIT}


def _roster() -> list[dict]:
    try:
        return external_agents.roster()
    except (external_agents.ExternalAgentsError, OSError, ValueError) as exc:
        raise _unavailable() from exc


def _agent(row: dict) -> dict:
    return {
        "name": _text(row["id"]),
        "platform": _text(row["platform_label"]),
        "active": bool(row["active"]),
        "blocked": bool(row["contained"] or row["lifecycle"] == "revoked"),
        "over_budget": bool(row["over_budget"]),
        "reported_spend_dollars": row["period_spent"],
        "budget_dollars": row["max_dollars"],
        "budget_period": row["period"],
    }


@router.get("/changed", operation_id="listChangedAgents")
def changed(request: Request) -> dict:
    require_page_permission(request, "/external-agents")
    now = datetime.now(UTC)
    week = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        rows = agent_drift.findings_reported_since(week.timestamp(), now=now.timestamp())
    except (agent_drift.AgentDriftError, external_agents.ExternalAgentsError, OSError, ValueError) as exc:
        raise _unavailable() from exc
    return {
        "since": week.isoformat(),
        **_page("changes", [{
            "name": _text(row["agent_id"]), "summary": _text(row["summary"]),
            "severity": row["severity"], "reported_at": _at(row["reported_at"]),
            "acknowledged": row["acknowledged"],
        } for row in rows]),
    }


@router.get("/approvals", operation_id="listWaitingApprovals")
def approvals(request: Request) -> dict:
    require_permission(request, "approve")
    from .content_access import can_read_approval

    world = _world()
    rows = [{"id": approval.id, "action": _text(approval.action), "risk": approval.risk,
             "requested_at": _at(approval.requested_at)}
            for approval in world.pending_approvals() if can_read_approval(request, approval, world)]
    return _page("approvals", rows)


@router.get("/attention", operation_id="listAgentsNeedingAttention")
def attention(request: Request) -> dict:
    require_page_permission(request, "/external-agents")
    rows = [_agent(row) for row in _roster()]
    return _page("agents", [row for row in rows if row["blocked"] or row["over_budget"]])


@router.get("/found", operation_id="listFoundAgents")
def found(request: Request) -> dict:
    require_page_permission(request, "/external-agents")
    if not external_agents.enabled():
        raise HTTPException(404, "Outside-agent governance is off.", headers=_PRIVATE)
    claimed = {str(row["external_ref"]).casefold() for row in _roster()}
    try:
        rows = agent_watch.unenrolled()
    except (agent_watch.AgentWatchError, OSError, ValueError) as exc:
        raise _unavailable() from exc
    return _page("agents", [{"name": _text(row["name"]), "platform": _text(row["platform"]),
                             "last_seen_at": _at(row["last_seen_at"])}
                            for row in rows if row["external_ref"].casefold() not in claimed])


@router.get("/agent", operation_id="getAgentStatus")
def agent_status(request: Request) -> dict:
    require_page_permission(request, "/external-agents")
    name = request.query_params.get("name", "").strip()
    if not name or len(name) > 128:
        raise HTTPException(422, "Enter an agent name from Outside agents.", headers=_PRIVATE)
    roster = _roster()
    rows = [row for row in roster if row["id"] == name] or [
        row for row in roster if row["id"].casefold() == name.casefold()
    ]
    if len(rows) != 1:
        raise HTTPException(404, "Use the exact enrolled name shown on Outside agents.", headers=_PRIVATE)
    row = rows[0]
    try:
        drift = agent_drift.detail(row["id"])
        platform = agent_watch.platform_view(row["id"])
    except (agent_drift.AgentDriftError, agent_watch.AgentWatchError, external_agents.ExternalAgentsError,
            OSError, ValueError) as exc:
        raise _unavailable() from exc
    return {"agent": {**_agent(row), "drift_status": _text(drift["state"].replace("_", " ")),
                      "missing_on_platform": platform["missing_on_platform"] if platform else None}}
