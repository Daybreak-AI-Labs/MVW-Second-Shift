"""Serve the files shipped in this package's ``static`` folder.

Each file gets its own route when the app starts, so a request can never name
a path outside the folder, and the sign-in rules (which compare route paths)
see the exact file path. These are ordinary routes, not a mount, so the app's
sign-in check applies to them like any other.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _serve(path: Path):
    async def static_file() -> FileResponse:
        return FileResponse(path)

    return static_file


for _path in sorted(p for p in STATIC_DIR.rglob("*") if p.is_file()):
    router.add_api_route(
        "/static/" + _path.relative_to(STATIC_DIR).as_posix(), _serve(_path), methods=["GET"], include_in_schema=False,
    )
