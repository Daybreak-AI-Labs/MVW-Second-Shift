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

from .auth import PUBLIC_STATIC_PATHS

router = APIRouter()
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _serve(path: Path, route_path: str):
    # The security middleware keeps every other response private. The static
    # version middleware upgrades matching public bundle URLs to immutable.
    headers = {"Cache-Control": "public, max-age=3600"} if route_path in PUBLIC_STATIC_PATHS else None

    async def static_file() -> FileResponse:
        return FileResponse(path, headers=headers)

    return static_file


for _path in sorted(p for p in STATIC_DIR.rglob("*") if p.is_file()):
    _route_path = "/static/" + _path.relative_to(STATIC_DIR).as_posix()
    router.add_api_route(_route_path, _serve(_path, _route_path), methods=["GET"], include_in_schema=False)
