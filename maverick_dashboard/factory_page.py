"""The agent factory's pages and API: draft an agent with a model, edit it, test it, submit it for release.

Reading needs ``view``; building, editing, testing and submitting need ``operate``; retiring needs ``admin``.
Approving a release is done on the Approvals page by a different person (see ``maverick.factory.release``).
Everything here fails plainly when the runtime is not installed or the model is not set up; nothing else in the
product depends on it.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, has_permission, require_permission

log = logging.getLogger("maverick.factory.web")
NO_STORE = {"Cache-Control": "private, no-store"}
router = APIRouter(tags=["agent-factory"])
_templates: Jinja2Templates | None = None


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BriefIn(_Strict):
    purpose: str = Field("", max_length=2000)
    users: str = Field("", max_length=1000)
    may: str = Field("", max_length=2000)
    must_not: str = Field("", max_length=2000)


class DraftIn(_Strict):
    brief: BriefIn


class CreateIn(_Strict):
    brief: BriefIn
    parts: dict[str, Any]


class EditIn(_Strict):
    parts: dict[str, Any]
    base_version: int = Field(ge=1)
    base_revision: int = Field(ge=1)


class CaseIn(_Strict):
    name: str = Field("", max_length=200)
    input: str = Field("", max_length=20_000)
    checks: list[dict[str, Any]] = Field(default_factory=list, max_length=20)


class ExportIn(_Strict):
    mint_key: bool = False
    skills_url: str = Field("", max_length=300)
    connection_id: str = Field("", max_length=500)
    approval_id: int | None = Field(None, ge=1)


class PushIn(_Strict):
    confirm_project: str = Field("", max_length=200)
    confirm_agent: str = Field("", max_length=200)
    skills_url: str = Field("", max_length=300)
    connection_id: str = Field("", max_length=500)
    mode: str = Field("create", max_length=20)


def _who(request: Request) -> str:
    return caller_principal(request) or "operator"


def _fail(exc: Exception) -> HTTPException:
    from maverick.factory import FactoryError

    if isinstance(exc, FactoryError):
        return HTTPException(status_code=exc.status, detail=str(exc))
    raise exc


def available() -> bool:
    from maverick.factory import runtime_available

    return runtime_available()


def require_installed() -> None:
    from maverick.factory import NOT_INSTALLED

    if not available():
        raise HTTPException(status_code=503, detail=NOT_INSTALLED)


def page(request: Request, name: str, **context: Any) -> HTMLResponse:
    from maverick.factory import NOT_INSTALLED

    assert _templates is not None
    return _templates.TemplateResponse(request, name, {
        "factory_installed": available(), "factory_not_installed": NOT_INSTALLED,
        "can_build": has_permission(request, "operate"), "can_admin": has_permission(request, "admin"),
        "can_approve": has_permission(request, "approve"), "me": _who(request), **context}, headers=NO_STORE)


def status_view() -> dict[str, Any]:
    from maverick.factory import definitions, foundry_push, settings, store

    if not available():
        return {"installed": False}
    s = settings.load()
    problems = settings.problems(s)
    return {"installed": True, "ready": not problems, "problems": problems, "provider": s.provider, "deployment": s.deployment,
            "has_prices": s.has_prices, "skills": definitions.skill_catalog(), "limits": definitions.LIMIT_LABELS,
            "max_test_cases": s.max_test_cases, "max_test_run_cost_dollars": s.max_test_run_cost_dollars,
            "max_test_run_seconds": s.max_test_run_seconds, "max_case_seconds": s.max_case_seconds,
            "check_kinds": store.CHECK_KINDS,
            "default_limits": definitions.default_limits(s), "foundry_push": foundry_push.status()}

# ---- pages ---------------------------------------------------------------------------------------------------


@router.get("/factory", response_class=HTMLResponse, include_in_schema=False)


async def factory_list(request: Request) -> HTMLResponse:
    require_permission(request, "view")
    agents: list[dict] = []
    if available():
        from maverick.factory import release, store, views

        def load() -> list[dict]:
            release.settle_all()
            return [views.summary_view(r) for r in store.list_agents()]

        agents = await run_in_threadpool(load)
    return page(request, "factory.html", agents=agents, status=await run_in_threadpool(status_view))


@router.get("/factory/new", response_class=HTMLResponse, include_in_schema=False)


async def factory_new(request: Request) -> HTMLResponse:
    require_permission(request, "operate")
    return page(request, "factory_new.html", status=await run_in_threadpool(status_view))


@router.get("/factory/{fac_id}", response_class=HTMLResponse, include_in_schema=False)


async def factory_agent(request: Request, fac_id: str) -> HTMLResponse:
    require_permission(request, "view")
    require_installed()
    from maverick.factory import release, store, views

    def load() -> dict:
        release.settle(fac_id)
        return views.agent_view(store.get(fac_id))

    try:
        view = await run_in_threadpool(load)
    except Exception as exc:
        raise _fail(exc) from exc
    return page(request, "factory_agent.html", agent=view, status=await run_in_threadpool(status_view))

# ---- API -----------------------------------------------------------------------------------------------------


@router.get("/api/v1/factory/status")


async def api_status(request: Request) -> dict:
    require_permission(request, "view")
    return await run_in_threadpool(status_view)


@router.get("/api/v1/factory/agents")


async def api_agents(request: Request) -> dict:
    require_permission(request, "view")
    require_installed()
    from maverick.factory import release, store, views

    def load() -> list[dict]:
        release.settle_all()
        return [views.summary_view(r) for r in store.list_agents()]

    return {"agents": await run_in_threadpool(load)}


@router.post("/api/v1/factory/draft")


async def api_draft(request: Request, body: DraftIn) -> dict:
    """Ask the model to propose a definition. Nothing is saved."""
    require_permission(request, "operate")
    require_installed()
    from maverick.factory import draft, settings

    def run() -> dict:
        brief = draft.clean_brief(body.brief.model_dump())
        return {"brief": brief, **draft.propose(brief, settings.load())}

    try:
        return await run_in_threadpool(run)
    except Exception as exc:
        raise _fail(exc) from exc


@router.post("/api/v1/factory/agents", status_code=201)


async def api_create(request: Request, body: CreateIn) -> dict:
    require_permission(request, "operate")
    require_installed()
    from maverick.factory import draft, settings, store, views

    def run() -> dict:
        brief = draft.clean_brief(body.brief.model_dump())
        return views.agent_view(store.create_agent(_who(request), brief, body.parts, settings.load()))

    try:
        return await run_in_threadpool(run)
    except Exception as exc:
        raise _fail(exc) from exc


@router.get("/api/v1/factory/agents/{fac_id}")


async def api_agent(request: Request, fac_id: str) -> dict:
    require_permission(request, "view")
    require_installed()
    from maverick.factory import release, store, views

    def load() -> dict:
        release.settle(fac_id)
        return views.agent_view(store.get(fac_id))

    try:
        return await run_in_threadpool(load)
    except Exception as exc:
        raise _fail(exc) from exc


def mutate(request: Request, fn):
    async def go() -> dict:
        require_permission(request, "operate")
        require_installed()
        from maverick.factory import views

        def run() -> dict:
            return views.agent_view(fn(_who(request)))

        try:
            return await run_in_threadpool(run)
        except Exception as exc:
            raise _fail(exc) from exc

    return go()


@router.put("/api/v1/factory/agents/{fac_id}/definition")


async def api_edit(request: Request, fac_id: str, body: EditIn) -> dict:
    from maverick.factory import settings, store

    return await mutate(request, lambda who: store.edit(fac_id, who, body.parts, settings.load(),
                                                        base_version=body.base_version, base_revision=body.base_revision))


@router.post("/api/v1/factory/agents/{fac_id}/cases", status_code=201)


async def api_case_add(request: Request, fac_id: str, body: CaseIn) -> dict:
    from maverick.factory import settings, store

    return await mutate(request, lambda who: store.add_case(fac_id, who, body.model_dump(), settings.load()))


@router.put("/api/v1/factory/agents/{fac_id}/cases/{case_id}")


async def api_case_change(request: Request, fac_id: str, case_id: str, body: CaseIn) -> dict:
    from maverick.factory import store

    return await mutate(request, lambda who: store.update_case(fac_id, who, case_id, body.model_dump()))


@router.delete("/api/v1/factory/agents/{fac_id}/cases/{case_id}")


async def api_case_delete(request: Request, fac_id: str, case_id: str) -> dict:
    from maverick.factory import store

    return await mutate(request, lambda who: store.delete_case(fac_id, who, case_id))


@router.post("/api/v1/factory/agents/{fac_id}/versions/{number}/tests", status_code=202)


async def api_run_tests(request: Request, fac_id: str, number: int) -> dict:
    from maverick.factory import settings, testing

    return await mutate(request, lambda who: testing.start(fac_id, number, who, settings.load()))


@router.post("/api/v1/factory/agents/{fac_id}/versions/{number}/submit", status_code=202)


async def api_submit(request: Request, fac_id: str, number: int) -> dict:
    from maverick.factory import release

    return await mutate(request, lambda who: release.submit(fac_id, number, who))


@router.post("/api/v1/factory/agents/{fac_id}/retire")


async def api_retire(request: Request, fac_id: str) -> dict:
    require_permission(request, "admin")
    require_installed()
    from maverick.factory import release, views

    try:
        return await run_in_threadpool(lambda: views.agent_view(release.retire(fac_id, _who(request))))
    except Exception as exc:
        raise _fail(exc) from exc


@router.post("/api/v1/factory/agents/{fac_id}/versions/{number}/exports/{target}")


async def api_export(request: Request, fac_id: str, number: int, target: str, body: ExportIn) -> JSONResponse:
    """A download for one place the released version can run (Azure, AWS or Foundry), and, when asked, a new access
    key for the agent, shown once in this answer. Needs ``admin``."""
    require_permission(request, "admin")
    require_installed()
    from maverick import external_agents as xa
    from maverick.factory import export

    from .approval_authority import require_approval_authority

    def run() -> dict:
        from maverick.factory import store

        authority = require_approval_authority(request, action="external_agents.credential_mint",
                                               resource=f"{store.get(fac_id)['agent_id']}:{export.KEY_SURFACE}") if body.mint_key else None
        return export.export_agent(fac_id, number, target, _who(request), mint_key=body.mint_key, skills_url=body.skills_url,
                                   connection_id=body.connection_id, mint_authority=authority, mint_approval_id=body.approval_id)

    try:
        return JSONResponse(await run_in_threadpool(run), headers=NO_STORE)
    except xa.MintApprovalPending as exc:
        return JSONResponse({"detail": str(exc), "status": "approval_required", "approval_id": exc.approval_id}, status_code=409, headers=NO_STORE)
    except Exception as exc:
        raise _fail(exc) from exc


@router.post("/api/v1/factory/agents/{fac_id}/versions/{number}/push/foundry")


async def api_push_foundry(request: Request, fac_id: str, number: int, body: PushIn) -> dict:
    """Create the agent in the configured Microsoft Foundry project. Off unless ``[factory.foundry] allow_push`` is true.
    Needs ``admin``; the request must name the project and agent; it is audited and never retried."""
    require_permission(request, "admin")
    require_installed()
    from maverick.factory import foundry_push

    try:
        return await run_in_threadpool(lambda: foundry_push.push(
            fac_id, number, _who(request), confirm_project=body.confirm_project, confirm_agent=body.confirm_agent,
            skills_url=body.skills_url, connection_id=body.connection_id, mode=body.mode))
    except Exception as exc:
        raise _fail(exc) from exc


def create_factory_router(templates: Jinja2Templates) -> APIRouter:
    """The factory's routes, rendering their pages with the dashboard's templates."""
    global _templates
    _templates = templates
    return router
