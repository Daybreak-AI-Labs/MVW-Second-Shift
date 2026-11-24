"""Administrator API for the settings that can be changed in the product.

``GET /api/v1/settings`` lists every editable setting with its current value and where the value
comes from. ``POST /api/v1/settings/{key}`` saves a new value and ``POST /api/v1/settings/{key}/reset``
takes the saved change away again. Every route needs the admin permission; a change also needs the
same-origin check and ``confirmed: true``, which the page sends after the person confirms.

A secret is never accepted or returned: a credential setting holds only the NAME of the variable
that holds it, and the answer says whether that variable is set. The rules, ranges and the layer
the values are kept in are in ``maverick.editable_settings``.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

router = APIRouter(prefix="/api/v1")


class ChangeIn(BaseModel):
    """The new value, and that the person confirmed it. Nothing else is accepted."""

    model_config = ConfigDict(extra="forbid")

    value: Any
    confirmed: Literal[True]


class ResetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: Literal[True]


def _same_origin(request: Request) -> None:
    from .app import _require_same_origin

    _require_same_origin(request)


async def _run(work):
    """Run one settings call off the event loop, turning its refusals into plain answers."""
    from maverick.audit.errors import AuditRefused
    from maverick.editable_settings import SettingRefused

    try:
        return await run_in_threadpool(work)
    except SettingRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    except AuditRefused as exc:
        raise HTTPException(
            status_code=503,
            detail="This could not be written to the audit log, so nothing was changed. Try again; if it keeps "
                   "failing, check where the audit log is stored.") from exc


def _actor(request: Request) -> str:
    return caller_principal(request) or "operator"


@router.get("/settings")
async def list_settings(request: Request) -> dict:
    """Every section and setting with its value and source (admin)."""
    require_permission(request, "admin")
    from maverick import editable_settings

    return await _run(editable_settings.describe)


@router.post("/settings/{key}")
async def change_setting(request: Request, key: str, body: ChangeIn) -> dict:
    """Save a new value for one setting (admin)."""
    require_permission(request, "admin")
    _same_origin(request)
    from maverick import editable_settings

    return await _run(lambda: editable_settings.change(key, body.value, actor=_actor(request)))


@router.post("/settings/{key}/reset")
async def reset_setting(request: Request, key: str, body: ResetIn) -> dict:
    """Take a saved change away, so the deployment's value applies again (admin)."""
    require_permission(request, "admin")
    _same_origin(request)
    from maverick import editable_settings

    return await _run(lambda: editable_settings.reset(key, actor=_actor(request)))
