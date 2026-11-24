"""The My agents page: the outside agents a signed-in person owns.

Any signed-in person with ``view`` can open it. Ownership is matched on what
the verified sign-in proves (a verified email and, when the sign-in carries it,
the Entra object id), never on a name; see :mod:`maverick.agent_owners`. The
page only reads: it runs no check and calls no platform. A person who also
holds the permission for an action finds it on the agent's own page and in
Approvals; everyone else is told who can act. Nothing here changes a record.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_permission, require_page_permission

log = logging.getLogger(__name__)


def request_identity(request: Request):
    """What this request's verified sign-in proves, for matching owners. Empty
    when nobody signed in as a person (no sign-in, or a shared access token)."""
    from maverick.agent_owners import Identity, identity_from_claims

    principal = getattr(getattr(request, "state", None), "principal", None)
    if principal is None:
        return Identity()
    return identity_from_claims(getattr(principal, "claims", None), issuer=str(getattr(principal, "issuer", "")),
                                subject=str(getattr(principal, "sub", "")))


def create_my_agents_page_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["my-agents-page"])

    @router.get("/my-agents", response_class=HTMLResponse, include_in_schema=False)
    async def my_agents_page(request: Request) -> HTMLResponse:
        require_page_permission(request, "/my-agents")
        from maverick import agent_owners, external_agents, owner_note

        who = request_identity(request)
        context = {"signed_in": bool(who), "agents": [], "unreadable": "", "enabled": external_agents.enabled(),
                   "can_admin": has_permission(request, "admin"), "can_respond": has_permission(request, "respond"),
                   "can_approve": has_permission(request, "approve"), "note": None}
        status = 200
        if who and context["enabled"]:
            try:
                views = await run_in_threadpool(agent_owners.owned_by, who)
            except agent_owners.AgentOwnersError as exc:
                context["unreadable"] = str(exc)
                status = 503
            else:
                for view in views:
                    view["needs"] = agent_owners.attention(view)
                context["agents"] = views
                context["note"] = await run_in_threadpool(owner_note.status)
        return templates.TemplateResponse(request, "my_agents.html", context, status_code=status,
                                          headers={"Cache-Control": "private, no-store"})

    return router
