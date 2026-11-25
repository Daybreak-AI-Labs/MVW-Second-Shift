"""API for the register of models and their statistical drift.

Operators (``/api/v1/models``): read the register and a model (``view``), add or
edit a model entered by hand and approve a baseline (``admin``), send a batch of
samples for a baseline or a check (``operate``), acknowledge a finding
(``respond``, which every role holding ``operate`` also holds).

An outside agent sends samples with its own access key, the same credential it
uses to report runs, at ``/api/v1/external/models``: it may list the models it
uses and send a batch for one of them, and nothing else.

A batch is bounded (size of the request, values in each series and in all,
features, embedding rows and width), a caller may send a limited number a
minute for one model, and a body with a field this API does not know is refused.
The samples are evaluated in memory and dropped: the answer holds only
statistics, and no error message repeats a value that was sent.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, StrictStr, ValidationError
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission
from .external_gateway import _require_agent

log = logging.getLogger("maverick.dashboard.models_api")

router = APIRouter(prefix="/api/v1")
agent_router = APIRouter(prefix="/api/v1/external/models", tags=["external-agents"])

#: The largest request body a batch may use; a batch is also capped by value counts.
MAX_BODY_BYTES = 256 * 1024
_RATE_BUCKET_CAP = 10_000
_rate_times: dict[tuple[str, str], deque[float]] = {}
_rate_lock = threading.Lock()

_Number = StrictInt | StrictFloat
_Scalar = StrictInt | StrictFloat | StrictStr


class ModelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    provider: str = Field(default="", max_length=80)
    purpose: str = Field(default="", max_length=300)
    owner: str = Field(default="", max_length=120)
    risk_tier: Literal["unrated", "low", "medium", "high"] = "unrated"
    agents: list[Annotated[str, Field(max_length=64)]] = Field(default_factory=list, max_length=200)


class ModelEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(default=None, max_length=80)
    purpose: str | None = Field(default=None, max_length=300)
    owner: str | None = Field(default=None, max_length=120)
    risk_tier: Literal["unrated", "low", "medium", "high"] | None = None
    agents: list[Annotated[str, Field(max_length=64)]] | None = Field(default=None, max_length=200)


class AcknowledgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: str = Field(min_length=1, max_length=200)


class SamplesIn(BaseModel):
    """One batch. Every field is optional except ``purpose``; at least one
    thing to monitor is needed."""

    model_config = ConfigDict(extra="forbid")

    purpose: Literal["baseline", "check"]
    numeric: dict[str, Annotated[list[_Number], Field(max_length=5000)]] = Field(default_factory=dict, max_length=16)
    categorical: dict[str, Annotated[list[StrictStr], Field(max_length=5000)]] = Field(default_factory=dict, max_length=16)
    predictions: Annotated[list[_Scalar], Field(max_length=5000)] | None = None
    labels: Annotated[list[_Scalar], Field(max_length=5000)] | None = None
    embeddings: Annotated[list[Annotated[list[_Number], Field(max_length=256)]], Field(max_length=200)] | None = None


# ------------------------------------------------------------------- helpers

def _plain(exc: ValidationError) -> str:
    """What was wrong with a body, without echoing any value that was sent."""
    parts = []
    for error in exc.errors()[:5]:
        where = ".".join(str(p) for p in error["loc"] if not isinstance(p, int)) or "the request"
        if error["type"] == "extra_forbidden":
            parts.append(f"{where} is not something this request accepts")
        elif error["type"] == "missing":
            parts.append(f"{where} is needed")
        else:
            parts.append(f"{where} is not valid ({error['msg'].split(',')[0].lower()})")
    return "The batch was refused: " + "; ".join(parts) + "."


async def _batch(request: Request) -> SamplesIn:
    """Read and validate a batch under a hard size cap."""
    declared = request.headers.get("content-length")
    try:
        if declared and int(declared) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="That batch is too large. Send fewer values at once.")
    except ValueError:
        raise HTTPException(status_code=400, detail="The request is not valid.") from None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="That batch is too large. Send fewer values at once.")
    try:
        return SamplesIn.model_validate_json(bytes(body))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_plain(exc)) from None


def _throttle(caller: str, model: str, per_minute: int) -> None:
    now = time.monotonic()
    bucket = (caller, model)
    from .worker_coordination import active_root, rate_allowed

    if (root := active_root()) is not None:
        if not rate_allowed(root, "models", bucket, per_minute, _RATE_BUCKET_CAP):
            raise HTTPException(status_code=429, detail="Too many batches are arriving. Try again in a minute.",
                                headers={"Retry-After": "60"})
        return
    with _rate_lock:
        if bucket not in _rate_times and len(_rate_times) >= _RATE_BUCKET_CAP:
            for key, window in tuple(_rate_times.items()):
                while window and now - window[0] >= 60:
                    window.popleft()
                if not window:
                    _rate_times.pop(key, None)
            if len(_rate_times) >= _RATE_BUCKET_CAP:
                raise HTTPException(status_code=429, detail="Too many batches are arriving. Try again in a minute.",
                                    headers={"Retry-After": "60"})
        window = _rate_times.setdefault(bucket, deque())
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= per_minute:
            raise HTTPException(
                status_code=429, headers={"Retry-After": "60"},
                detail=f"At most {per_minute} batches a minute may be sent for one model. Wait a minute and send again.")
        window.append(now)


async def _call(work):
    """Run one register call off the event loop, turning its refusals into plain HTTP answers."""
    from maverick import model_drift, model_register
    from maverick.audit.errors import AuditRefused

    try:
        return await run_in_threadpool(work)
    except model_register.ModelNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except model_register.ModelConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except model_register.ModelStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (model_register.ModelRegisterError, model_drift.SampleError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail="This could not be written to the audit log, so nothing was "
                                                    "changed. Try again; if it keeps failing, check where the "
                                                    "audit log is stored.") from exc


def _samples(batch: SamplesIn) -> dict:
    return {"numeric": batch.numeric, "categorical": batch.categorical, "predictions": batch.predictions,
            "labels": batch.labels, "embeddings": batch.embeddings}


def _answer(out: dict) -> dict:
    return {"ok": True, **out}


# ------------------------------------------------------------------ operators

@router.get("/models")
async def list_models(request: Request) -> dict:
    """The register: every model with its agents, status and last check."""
    require_permission(request, "view")
    from maverick import model_drift, model_register

    def read() -> dict:
        found = model_register.sync()
        return {"enabled": model_drift.settings()["enable"], "models": model_register.list_models(),
                "problems": found["problems"]}

    return await _call(read)


@router.get("/models/{model_id}")
async def read_model(request: Request, model_id: str) -> dict:
    """One model with its baseline, recent checks and findings."""
    require_permission(request, "view")
    from maverick import model_register

    return await _call(lambda: model_register.get(model_id))


@router.post("/models", status_code=201)
async def add_model(request: Request, body: ModelIn) -> dict:
    """Enter a model by hand (admin)."""
    require_permission(request, "admin")
    from maverick import model_register

    actor = caller_principal(request) or "admin"
    fields = body.model_dump(exclude={"name"})
    return await _call(lambda: model_register.add(body.name, actor=actor, **fields))


@router.patch("/models/{model_id}")
async def edit_model(request: Request, model_id: str, body: ModelEdit) -> dict:
    """Describe or change a model (admin). Only the fields sent change."""
    require_permission(request, "admin")
    from maverick import model_register

    actor = caller_principal(request) or "admin"
    fields = body.model_dump(exclude_unset=True)
    if any(value is None for value in fields.values()):
        raise HTTPException(status_code=422, detail="A field that is sent needs a value; leave a field out to keep it.")
    return await _call(lambda: model_register.edit(model_id, actor=actor, **fields))


@router.post("/models/{model_id}/samples")
async def send_samples(request: Request, model_id: str) -> dict:
    """Send a batch for a baseline or a check (operate). The batch is evaluated
    and dropped; the answer holds statistics only."""
    require_permission(request, "operate")
    from maverick import model_drift, model_register

    by = caller_principal(request) or "operator"
    batch = await _batch(request)
    _throttle(by, model_id, model_drift.settings()["batches_per_minute"])
    return _answer(await _call(lambda: model_register.receive_samples(
        model_id, _samples(batch), purpose=batch.purpose, by=by)))


@router.post("/models/{model_id}/baseline/approve")
async def approve_baseline(request: Request, model_id: str) -> dict:
    """Approve the baseline batch that is waiting (admin)."""
    require_permission(request, "admin")
    from maverick import model_register

    actor = caller_principal(request) or "admin"
    return await _call(lambda: model_register.approve_baseline(model_id, actor=actor))


@router.post("/models/{model_id}/findings/acknowledge")
async def acknowledge_finding(request: Request, model_id: str, body: AcknowledgeIn) -> dict:
    """Acknowledge one open finding (respond)."""
    require_permission(request, "respond")
    from maverick import model_register

    actor = caller_principal(request) or "operator"
    return await _call(lambda: model_register.acknowledge(model_id, body.finding, actor=actor))


# --------------------------------------------------------------------- agents

@agent_router.get("")
async def agent_models(agent_id: str = Depends(_require_agent)) -> dict:
    """The models this agent uses, so it can find the id to send samples to."""
    from maverick import model_register

    def read() -> dict:
        model_register.sync()
        return {"models": [{"id": m["id"], "name": m["name"], "status": m["status"],
                            "has_baseline": m["status"] in ("monitored", "drifting")}
                           for m in model_register.models_for_agent(agent_id)]}

    return await _call(read)


@agent_router.post("/{model_id}/samples")
async def agent_send_samples(request: Request, model_id: str, agent_id: str = Depends(_require_agent)) -> dict:
    """An agent sends a batch for a model it uses. The key's agent must be
    listed among the model's agents; any other model is refused."""
    from maverick import model_drift, model_register

    batch = await _batch(request)
    _throttle(f"agent:{agent_id}", model_id, model_drift.settings()["batches_per_minute"])

    def send() -> dict:
        try:
            allowed = agent_id in model_register.agents_using(model_id, refresh=True)
        except model_register.ModelNotFound:
            allowed = False
        if not allowed:
            raise PermissionError
        return model_register.receive_samples(model_id, _samples(batch), purpose=batch.purpose, by=f"agent:{agent_id}")

    try:
        return _answer(await _call(send))
    except PermissionError:
        raise HTTPException(status_code=403, detail="This agent is not listed as using that model.") from None
