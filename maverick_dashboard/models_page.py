"""The Models pages: the register, and one model with its baseline, checks and findings.

``/models`` lists every model with its agents, status and last check;
``/models/{id}`` shows one model: what people say about it, the baseline
(approved, or waiting for approval), the recent checks as a table and a small
chart, and its findings with a button to acknowledge each.

The pages only read, apart from bringing the register up to date with the models
agents report (``model_register.sync``). Everything that changes a record is a
button that calls ``/api/v1/models``, so it has the same permission checks as
the API. The chart is plain SVG built here from numbers only: no name or text
from a model or an agent is written into it except as escaped template text.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_permission, require_permission

log = logging.getLogger(__name__)

CHART_WIDTH = 560
CHART_HEIGHT = 180
_PAD_LEFT, _PAD_RIGHT, _PAD_TOP, _PAD_BOTTOM = 44, 12, 12, 24


def chart(checks: list[dict], threshold: float) -> dict | None:
    """Points for the chart of the largest population stability index in each
    check, oldest left, with the limit as a dashed line. ``None`` when no check
    has a value to draw. Every number is rounded here; nothing else is returned."""
    series = [c for c in reversed(checks) if isinstance(c.get("max_psi"), (int, float))]
    if not series:
        return None
    values = [float(c["max_psi"]) for c in series]
    top = max(max(values), float(threshold)) * 1.15 or 1.0
    width = CHART_WIDTH - _PAD_LEFT - _PAD_RIGHT
    height = CHART_HEIGHT - _PAD_TOP - _PAD_BOTTOM

    def x(index: int) -> float:
        return _PAD_LEFT + (width * index / (len(values) - 1) if len(values) > 1 else width / 2)

    def y(value: float) -> float:
        return _PAD_TOP + height - height * value / top

    points = [{"x": round(x(i), 1), "y": round(y(v), 1), "value": round(v, 3), "at": series[i]["at"]}
              for i, v in enumerate(values)]
    return {
        "width": CHART_WIDTH, "height": CHART_HEIGHT, "left": _PAD_LEFT, "right": CHART_WIDTH - _PAD_RIGHT,
        "bottom": _PAD_TOP + height, "top": _PAD_TOP,
        "points": points, "line": " ".join(f"{p['x']},{p['y']}" for p in points),
        "limit_y": round(y(float(threshold)), 1), "limit": round(float(threshold), 3), "max": round(top, 3),
        "over": [p for p, v in zip(points, values, strict=True) if v >= float(threshold)],
    }


def create_models_page_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["models-page"])

    @router.get("/models", response_class=HTMLResponse, include_in_schema=False)
    async def models_page(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        from maverick import model_drift, model_register

        def read() -> dict:
            problems: list[str] = []
            try:
                problems = model_register.sync()["problems"]
                models = model_register.list_models()
            except model_register.ModelRegisterError as exc:
                return {"models": [], "problems": [], "unreadable": str(exc)}
            return {"models": models, "problems": problems, "unreadable": ""}

        found = await run_in_threadpool(read)
        return templates.TemplateResponse(
            request, "models.html",
            {**found, "enabled": model_drift.settings()["enable"], "can_admin": has_permission(request, "admin"),
             "risk_tiers": model_register.RISK_TIERS},
            status_code=503 if found["unreadable"] else 200, headers={"Cache-Control": "private, no-store"})

    @router.get("/models/{model_id}", response_class=HTMLResponse, include_in_schema=False)
    async def model_page(request: Request, model_id: str) -> HTMLResponse:
        require_permission(request, "view")
        from maverick import model_register

        try:
            found = await run_in_threadpool(model_register.get, model_id)
        except model_register.ModelNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except model_register.ModelRegisterError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return templates.TemplateResponse(
            request, "model_detail.html",
            {"m": found, "chart": chart(found["checks"], found["settings"]["psi_threshold"]),
             "can_admin": has_permission(request, "admin"), "can_operate": has_permission(request, "operate"),
             "can_respond": has_permission(request, "respond"), "risk_tiers": model_register.RISK_TIERS},
            headers={"Cache-Control": "private, no-store"})

    return router
