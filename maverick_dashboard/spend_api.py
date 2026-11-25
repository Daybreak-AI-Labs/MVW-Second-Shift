"""Permission-checked spend page, JSON report and CSV export."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from maverick.external_agents import ExternalAgentsError
from maverick.spend_reporting import report

from ._shared import _world
from .auth import require_permission

_HEADERS = {"Cache-Control": "private, no-store"}
_TABLES = ("agents", "departments", "platforms", "months", "budgets")
_COLUMNS = ("table", "label", "dollars", "runs", "budget_period", "spent_dollars", "limit_dollars",
            "projected_dollars", "over_limit", "projected_over_limit")


def _report(request: Request) -> dict:
    require_permission(request, "view")
    try:
        return report(_world())
    except (ExternalAgentsError, OSError, ValueError) as exc:
        raise HTTPException(503, "Saved spending records could not be read. Try again.", headers=_HEADERS) from exc


def _safe_label(value: str) -> str:
    """Keep exported labels as plain cells in spreadsheet programs."""
    return "'" + value if value.startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")) else value


def create_spend_router(templates) -> APIRouter:
    router = APIRouter(tags=["Spend"])

    @router.get("/spend", response_class=HTMLResponse)
    def spend_page(request: Request) -> Response:
        return templates.TemplateResponse(request, "spend.html", {"spend": _report(request)}, headers=_HEADERS)

    @router.get("/api/v1/spend")
    def spend_json(request: Request) -> JSONResponse:
        return JSONResponse(_report(request), headers=_HEADERS)

    @router.get("/api/v1/spend.csv")
    def spend_csv(request: Request) -> Response:
        data = _report(request)
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=_COLUMNS)
        writer.writeheader()
        for table in _TABLES:
            for row in data[table]:
                writer.writerow({**row, "table": table, "label": _safe_label(row["label"])})
        return Response(
            output.getvalue(), media_type="text/csv",
            headers={**_HEADERS, "Content-Disposition": 'attachment; filename="second-shift-spend.csv"'},
        )

    return router
