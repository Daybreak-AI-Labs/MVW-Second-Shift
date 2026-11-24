"""People search for the owner picker on the add-agent form.

One read-only route. It needs ``admin`` (the people who may add agents) and
asks the Entra directory (``maverick.entra_directory``) for people whose name or
email starts with what was typed. The answer holds, for each person, only a
display name, an email, an object id and a job title. With the directory off it
says so and finds nobody; the form then takes a typed email as it always did.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter(prefix="/api/v1")


@router.get("/directory/people")
async def directory_people(request: Request, q: str = "") -> dict:
    """People matching ``q`` (at most ten); ``enabled`` is false when the
    directory is off. Needs ``admin``."""
    require_permission(request, "admin")
    from maverick import entra_directory

    if not entra_directory.enabled():
        return {"enabled": False, "people": []}
    try:
        people = await run_in_threadpool(entra_directory.search_people, q)
    except entra_directory.DirectoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {"enabled": True, "people": people}
