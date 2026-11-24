"""The two web calls Copilot Studio makes to Second Shift for external threat
detection: ``POST /copilot-studio/validate`` and
``POST /copilot-studio/analyze-tool-execution`` (both with
``?api-version=2025-05-01``; the version is not checked, as the contract asks).

These are machine calls from Microsoft, so they sit outside the browser
sign-in and the same-origin check and carry a Microsoft Entra access token
instead (checked in ``maverick.copilot_studio_gate.verify_token``). Anything
that fails the token check gets 401 and the documented error body.

A decision is answered inside one second whatever happens: the work runs off
the event loop under a deadline, never calls another service, and an answer
that is not ready in time becomes the administrator's ``on_error`` choice. The
body is read raw, never through a request model, so an error can never echo
what the person typed. Nothing from the request body is logged.

``GET /api/v1/copilot-studio-gate`` (view permission) lists the agents that
asked while not enrolled, so an administrator can enroll them.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from maverick import copilot_studio_gate as gate

from .auth import require_permission

log = logging.getLogger("maverick.dashboard.copilot_studio_gate")

router = APIRouter()

#: Copilot Studio gives up after one second. Leave room for the response.
_DEADLINE_SECONDS = 0.85
#: The most time the token check may take before the call is given up on.
_TOKEN_SECONDS = 0.45
_CORRELATION = re.compile(r"[0-9a-fA-F-]{8,64}")


def _error(status: int, code: int, message: str, request: Request | None = None) -> JSONResponse:
    headers = {}
    correlation = request.headers.get("x-ms-correlation-id", "") if request is not None else ""
    if _CORRELATION.fullmatch(correlation):
        headers["x-ms-correlation-id"] = correlation
    return JSONResponse({"errorCode": code, "message": message, "httpStatus": status},
                        status_code=status, headers=headers)


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > gate.MAX_BODY_BYTES:
                raise gate.BadRequest("The request is too large.", 413, gate.ERR_TOO_LARGE)
        except ValueError:
            raise gate.BadRequest("Content-Length is not a number.") from None
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > gate.MAX_BODY_BYTES - len(body):
            raise gate.BadRequest("The request is too large.", 413, gate.ERR_TOO_LARGE)
        body.extend(chunk)
    return bytes(body)


async def _authenticate(request: Request, started: float):
    """The settings and verified token claims, or the error response to send."""
    settings = await run_in_threadpool(gate.load_settings)
    remaining = min(_TOKEN_SECONDS, _DEADLINE_SECONDS - (time.monotonic() - started))
    try:
        await asyncio.wait_for(
            run_in_threadpool(gate.verify_token, request.headers.get("authorization"), settings),
            timeout=max(remaining, 0.05))
    except gate.TokenRejected:
        return settings, _error(401, gate.ERR_AUTH, "The access token is not accepted.", request)
    except (gate.TokenUnavailable, TimeoutError):
        return settings, _error(503, gate.ERR_UNAVAILABLE,
                                "Second Shift could not check the access token just now.", request)
    return settings, None


@router.post("/copilot-studio/validate")
async def validate(request: Request):
    """Setup check: ready only when Second Shift can make decisions."""
    started = time.monotonic()
    try:
        await _read_body(request)
    except gate.BadRequest as exc:
        return _error(exc.status, exc.code, exc.message, request)
    settings, failure = await _authenticate(request, started)
    if failure is not None:
        return failure
    problem = await run_in_threadpool(gate.ready_problem, settings)
    if problem:
        return _error(503, gate.ERR_UNAVAILABLE, problem, request)
    return JSONResponse({"isSuccessful": True, "status": "OK"})


@router.post("/copilot-studio/analyze-tool-execution")
async def analyze_tool_execution(request: Request):
    """Allow or block one proposed tool call."""
    started = time.monotonic()
    try:
        body = await _read_body(request)
    except gate.BadRequest as exc:
        return _error(exc.status, exc.code, exc.message, request)
    settings, failure = await _authenticate(request, started)
    if failure is not None:
        return failure
    try:
        tool_request = gate.parse_request(body)
    except gate.BadRequest as exc:
        return _error(exc.status, exc.code, exc.message, request)
    finally:
        del body  # the prompt, chat history and tool outputs are not kept
    remaining = _DEADLINE_SECONDS - (time.monotonic() - started)
    try:
        verdict = await asyncio.wait_for(
            run_in_threadpool(gate.decide, tool_request, settings), timeout=max(remaining, 0.05))
    except TimeoutError:
        log.warning("copilot_studio_gate: no decision within the time limit")
        verdict = gate.Verdict(settings.on_error != "allow", "timeout",
                               "Second Shift blocked this action: it could not check this request "
                               "in time. Try again shortly.", gate.CODE_UNAVAILABLE)
    log.debug("copilot_studio_gate: %s in %.0f ms", verdict.rule, (time.monotonic() - started) * 1000)
    return JSONResponse(verdict.body())


@router.get("/api/v1/copilot-studio-gate")
async def seen_agents(request: Request) -> dict:
    """Agents that asked about a tool while not enrolled in Second Shift."""
    require_permission(request, "view")
    rows = await run_in_threadpool(gate.seen_unenrolled)
    return {"not_enrolled": rows}
