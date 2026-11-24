"""The Settings page: the everyday settings, changed in the product by an administrator.

Each setting shows its current value, where that value comes from and a one-line
explanation. A change is confirmed in the page and saved through
``/api/v1/settings``, so it has the same permission, same-origin and audit checks as the API. A setting
the deployment locks is shown but cannot be changed. The page never receives a secret: a credential
setting holds a variable name, and the page shows whether that variable is set.

Only administrators may open it.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import require_permission


def create_settings_page_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["settings-page"])

    @router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
    async def settings_page(request: Request) -> HTMLResponse:
        require_permission(request, "admin")
        from maverick import editable_settings

        found = await run_in_threadpool(editable_settings.describe)
        return templates.TemplateResponse(
            request, "settings.html", found, headers={"Cache-Control": "private, no-store"})

    return router
