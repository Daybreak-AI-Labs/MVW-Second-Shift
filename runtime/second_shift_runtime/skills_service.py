"""``serve-skills``: the agent's skills as an HTTP service, so an agent that runs somewhere else can still be governed.

Microsoft Foundry Agent Service runs a prompt agent itself, and has no step where a customer's code can check a tool
call before Foundry makes it (https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi). So the agent's
tools are this service. Each skill in the definition is one operation, ``POST /skills/<skill name>``, described by an
OpenAPI 3.0 file that Foundry's OpenAPI tool accepts (``build_openapi``). Every call is screened with Second Shift
as the agent before the skill runs, waits for a person when Second Shift says one must decide, obeys the emergency
stop, and is reported. If Second Shift cannot be reached, nothing runs.

How calls are grouped into runs. Foundry sends no conversation id to a tool, so this service cannot tell one
conversation from the next. One run is open at a time: it opens at the first call, stays open while calls keep
arriving, and is finished (and reported) when no call has arrived for ``idle_seconds`` (default 120), when it has
lasted the definition's ``limits.max_seconds``, or when Second Shift tells it to stop. The definition's
``limits.max_tool_calls`` is the most calls in one run; a call beyond it is refused with kind ``limit``. The run
reports the build (version, config digest and model) the same way a run of the runtime does. It cannot report the
model's cost: the model runs inside Foundry, so the cost is 0 and the report says so.

Standard library and httpx only. The service's own key (``x-api-key``) and the agent's Second Shift key are read from
environment variables by NAME; a key is never in the definition, a log or an answer.
"""
from __future__ import annotations

import base64
import copy
import hmac
import json
import logging
import re
import shutil
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .definition import AgentDefinition
from .governance import Governance, GovernanceError
from .loop import DETAIL_CHARS, declared_build
from .skills import BoundSkill, SkillContext, SkillError, resolve_skills

log = logging.getLogger("second_shift_runtime.skills_service")

#: The header Foundry puts the key in. A Foundry "Custom keys" connection uses this as its key name and the key as its
#: value; the OpenAPI file's single apiKey scheme must carry the same name.
#: https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi (section "Authenticate with API key")
API_KEY_HEADER = "x-api-key"
SECURITY_SCHEME = "secondShiftSkillsKey"
DEFAULT_KEY_ENV = "SECOND_SHIFT_SKILLS_KEY"
MAX_BODY_BYTES = 1_000_000
MAX_INLINE_FILE_BYTES = 1_000_000
MAX_REPORT_STEPS = 50
#: HTTP status for each refusal kind; ``kind`` is always in the body as well.
STATUS_FOR_KIND = {"denied": 403, "contained": 403, "approval_required": 408, "halted": 503, "limit": 429, "unavailable": 503}
RETRY_LATER = frozenset({"approval_required", "limit", "unavailable"})

_OPERATION_ID = re.compile(r"^[A-Za-z_-]+$")  # "only letters, -, and _" per Microsoft's page
_BODY_TYPES = {"application/json", "application/json-patch+json"}
_JSON_ONLY_KEYS = ("$schema", "const", "examples", "$defs")


# ---------------------------------------------------------------------------------------------------------------
# The OpenAPI description
# ---------------------------------------------------------------------------------------------------------------

def to_openapi30(schema: Any) -> Any:
    """A skill's JSON schema as an OpenAPI 3.0 schema object: a list of types becomes ``anyOf`` (with
    ``nullable`` for null), and keywords OpenAPI 3.0 does not have are dropped."""
    if isinstance(schema, list):
        return [to_openapi30(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out = {key: ({name: to_openapi30(sub) for name, sub in value.items()} if key == "properties" and isinstance(value, dict)
                 else to_openapi30(value))
           for key, value in schema.items() if key not in _JSON_ONLY_KEYS}
    kind = out.get("type")
    if isinstance(kind, list):
        names = [k for k in kind if k != "null"]
        del out["type"]
        if len(names) != len(kind):
            out["nullable"] = True
        if len(names) == 1:
            out["type"] = names[0]
        elif names:
            out["anyOf"] = [{"type": k} for k in names]
    return out


def build_openapi(definition: AgentDefinition, server_url: str) -> dict[str, Any]:
    """The OpenAPI 3.0 description of the agent's skills, for Foundry's OpenAPI tool.

    Foundry's rules (https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi): OpenAPI 3.0 or 3.1; every
    operation has an ``operationId`` of letters, ``-`` and ``_`` only; request bodies are ``application/json``; one
    apiKey security scheme per tool, named in ``components.securitySchemes`` and listed in ``security``, with the key
    itself in a project connection and never in this file."""
    parts = urlsplit(server_url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.query or parts.fragment:
        raise ValueError("The skills service address must be an https:// address with no user name, query or fragment.")
    skills = resolve_skills(definition.skills)
    if not skills:
        raise ValueError("The agent has no skills, so there is nothing to serve.")
    error = {"type": "object", "properties": {
        "status": {"type": "string", "description": "refused"},
        "kind": {"type": "string", "enum": ["denied", "approval_required", "halted", "contained", "limit", "unavailable"],
                 "description": "Why Second Shift did not allow the action. limit, unavailable and approval_required "
                                "mean try again later; the others mean no."},
        "reason": {"type": "string"}, "retry_later": {"type": "boolean"}}}
    ok = {"type": "object", "properties": {
        "status": {"type": "string", "description": "ok, or error when the skill could not do what was asked."},
        "result": {"type": "string"},
        "files": {"type": "array", "items": {"type": "object", "properties": {
            "name": {"type": "string"}, "size": {"type": "integer"}, "sha256": {"type": "string"},
            "content_base64": {"type": "string"}}}}}}
    paths: dict[str, Any] = {}
    for name, bound in skills.items():
        if not _OPERATION_ID.match(name):
            raise ValueError(f"The skill name {name!r} cannot be an operationId: Foundry allows only letters, - and _.")
        description = bound.skill.description
        paths[f"/skills/{name}"] = {"post": {
            "operationId": name,
            "summary": description.split(".")[0][:120] or name,
            "description": description,
            "requestBody": {"required": True, "content": {"application/json": {"schema": to_openapi30(bound.skill.input_schema)}}},
            "responses": {
                "200": {"description": "What the skill returned.", "content": {"application/json": {"schema": ok}}},
                "default": {"description": "Second Shift did not allow the action, or the service could not run it.",
                            "content": {"application/json": {"schema": error}}}},
        }}
    return {
        "openapi": "3.0.3",
        "info": {"title": f"{definition.name} skills", "version": definition.version,
                 "description": "The skills of one agent. Each call is checked with Second Shift before it runs."},
        "servers": [{"url": server_url.rstrip("/")}],
        "paths": paths,
        "components": {"securitySchemes": {SECURITY_SCHEME: {"type": "apiKey", "in": "header", "name": API_KEY_HEADER}}},
        "security": [{SECURITY_SCHEME: []}],
    }


def check_foundry_openapi(spec: Any) -> list[str]:
    """Problems with an OpenAPI file against the rules Microsoft documents for the Foundry OpenAPI tool. Empty when
    it meets them. (Foundry's own validation is not reachable from here, so this is the documented rules only.)"""
    problems: list[str] = []
    if not isinstance(spec, dict):
        return ["The file is not a JSON object."]
    version = str(spec.get("openapi", ""))
    if not (version.startswith("3.0") or version.startswith("3.1")):
        problems.append("openapi must be 3.0.x or 3.1.x.")
    servers = spec.get("servers")
    if not isinstance(servers, list) or not servers or not str((servers[0] or {}).get("url", "")).startswith("https://"):
        problems.append("servers must name an https address.")
    schemes = (spec.get("components") or {}).get("securitySchemes") or {}
    api_keys = [n for n, s in schemes.items() if isinstance(s, dict) and s.get("type") == "apiKey"]
    if len(schemes) != 1 or len(api_keys) != 1:
        problems.append("There must be exactly one security scheme, of type apiKey.")
    else:
        scheme = schemes[api_keys[0]]
        if scheme.get("in") not in ("header", "query") or not scheme.get("name"):
            problems.append("The apiKey scheme needs 'in' (header or query) and 'name'.")
        if {next(iter(r), None) for r in spec.get("security", [])} != {api_keys[0]}:
            problems.append("security must list the apiKey scheme.")
    seen: set[str] = set()
    operations = 0
    for path, item in (spec.get("paths") or {}).items():
        for method, op in (item or {}).items():
            operations += 1
            where = f"{method.upper()} {path}"
            op_id = op.get("operationId") if isinstance(op, dict) else None
            if not isinstance(op_id, str) or not _OPERATION_ID.match(op_id):
                problems.append(f"{where}: operationId is required and may hold only letters, - and _.")
            elif op_id in seen:
                problems.append(f"{where}: operationId {op_id} is used twice.")
            else:
                seen.add(op_id)
            if not isinstance(op, dict):
                continue
            content = (op.get("requestBody") or {}).get("content") or {}
            for media in content:
                if media not in _BODY_TYPES:
                    problems.append(f"{where}: request body type {media} is not supported (use application/json).")
            if "parameters" in op and any(p.get("in") == "header" and p.get("name", "").lower() == API_KEY_HEADER
                                          for p in op["parameters"]):
                problems.append(f"{where}: the key must not be an operation parameter.")
    if not operations:
        problems.append("There are no operations.")
    if version.startswith("3.0"):
        problems.extend(_schema_problems(spec.get("paths"), "paths"))
    return problems


def _schema_problems(node: Any, where: str) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        if isinstance(node.get("type"), list):
            found.append(f"{where}: a list of types is not valid in OpenAPI 3.0.")
        for key in ("$schema", "const"):
            if key in node:
                found.append(f"{where}: {key} is not valid in OpenAPI 3.0.")
        for key, value in node.items():
            found.extend(_schema_problems(value, f"{where}.{key}"))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found.extend(_schema_problems(value, f"{where}[{i}]"))
    return found


# ---------------------------------------------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class Reply:
    status: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


def refusal(kind: str, reason: str) -> Reply:
    status = STATUS_FOR_KIND.get(kind, 403)
    headers = {"Retry-After": "30"} if kind in RETRY_LATER else {}
    return Reply(status, {"status": "refused", "kind": kind, "reason": reason, "retry_later": kind in RETRY_LATER}, headers)


@dataclass
class _Run:
    gov: Governance
    started: float
    last_activity: float
    in_flight: int = 0
    tool_calls: int = 0
    refused: int = 0
    tools: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)


GovernanceFactory = Callable[[], Governance]


class SkillRuns:
    """The calls of one agent, grouped into governed runs (see the module text)."""

    def __init__(self, definition: AgentDefinition, output_root: Path, *, env: Mapping[str, str] | None = None,
                 governance_factory: GovernanceFactory | None = None, idle_seconds: float = 120.0,
                 approval_wait: float = 60.0, clock: Callable[[], float] = time.monotonic,
                 skill_transport: httpx.BaseTransport | None = None, resolver: Callable[[str], list[str]] | None = None):
        import os
        self.definition = definition
        self.skills: dict[str, BoundSkill] = resolve_skills(definition.skills)
        self.output_root = Path(output_root)
        self.env: Mapping[str, str] = os.environ if env is None else env
        self._factory = governance_factory or self._default_governance
        self.idle_seconds, self.approval_wait, self._clock = idle_seconds, approval_wait, clock
        self._skill_transport, self._resolver = skill_transport, resolver
        self._lock = threading.Lock()
        self._run: _Run | None = None

    def _default_governance(self) -> Governance:
        gov = self.definition.governance
        address, key = self.env.get(gov.address_env, ""), self.env.get(gov.agent_key_env, "")
        if not address or not key:
            raise GovernanceError(f"Second Shift is not set up: {gov.address_env} and {gov.agent_key_env} must both be set. "
                                  "This service does not act without Second Shift.", "unavailable")
        return Governance(address, key, approval_wait=self.approval_wait)

    # -- the run -------------------------------------------------------------------------------------------

    def _acquire(self) -> _Run:
        """The open run (or a new one), with this call counted in flight. Raises GovernanceError when no run can be had."""
        with self._lock:
            now = self._clock()
            run = self._run
            if run is not None and self._finished(run, now):
                self._finish(run, "The run ended.")
                self._run = run = None
            if run is None:
                gov = self._factory()
                try:
                    gov.start(self.definition.name, declared=declared_build(self.definition))
                    gov.start_beating()
                except GovernanceError:
                    gov.close()
                    raise
                run = self._run = _Run(gov, now, now)
            run.in_flight += 1
            return run

    def _finished(self, run: _Run, now: float) -> bool:
        if run.gov.stop_reason and run.in_flight == 0:
            return True
        if run.in_flight:
            return False
        return now - run.last_activity > self.idle_seconds or now - run.started > self.definition.limits.max_seconds

    def _release(self, run: _Run) -> None:
        with self._lock:
            run.in_flight -= 1
            run.last_activity = self._clock()

    def close_idle(self) -> bool:
        """Finish the open run if it has been quiet too long (called by a timer). Returns whether one was finished."""
        with self._lock:
            run = self._run
            if run is None or not self._finished(run, self._clock()):
                return False
            self._finish(run, "The run ended.")
            self._run = None
            return True

    def close(self, reason: str = "The service was stopped.") -> None:
        """Finish the open run now, as a failure (used when the service stops)."""
        with self._lock:
            if self._run is not None:
                self._finish(self._run, reason, stopped=True)
                self._run = None

    def _finish(self, run: _Run, reason: str, *, stopped: bool = False) -> None:
        failed = stopped or bool(run.gov.stop_reason)
        if failed:
            summary = run.gov.stop_reason or reason
        else:
            summary = f"Finished with {run.tool_calls} tool call(s) and {run.refused} refused."
        summary += " The model's cost is not counted here: the model runs on the platform that hosts the agent."
        steps = run.steps if len(run.steps) <= MAX_REPORT_STEPS else [*run.steps[: MAX_REPORT_STEPS - 1], "(more steps not listed)"]
        report = {
            "outcome": "failure" if failed else "success", "summary": summary[:4000], "steps": steps,
            "cost_dollars": 0.0, "input_tokens": 0, "output_tokens": 0, "tool_calls": run.tool_calls, "tools": run.tools,
            "declared": declared_build(self.definition), "duration_seconds": round(self._clock() - run.started, 3),
            "idempotency_key": uuid.uuid4().hex,
        }
        try:
            run.gov.finish(report)
        except GovernanceError:
            log.warning("the run report could not be sent")
        run.gov.close()

    # -- one call ------------------------------------------------------------------------------------------

    def call(self, name: str, args: dict[str, Any]) -> Reply:
        bound = self.skills.get(name)
        if bound is None:
            return Reply(404, {"status": "error", "result": f"There is no skill called {name!r}."})
        try:
            run = self._acquire()
        except GovernanceError as exc:
            return refusal(exc.kind, str(exc))
        try:
            if run.gov.stop_reason:
                from .governance import kind_from_reason
                return refusal(kind_from_reason(run.gov.stop_reason), run.gov.stop_reason)
            if run.tool_calls + run.in_flight > self.definition.limits.max_tool_calls:
                run.refused += 1
                return refusal("limit", f"This agent may make {self.definition.limits.max_tool_calls} tool calls in one run, "
                                        f"and has made them. The run ends after {self.idle_seconds:g} seconds without a call.")
            try:
                detail = bound.skill.describe(args)[:DETAIL_CHARS]
            except Exception:
                detail = f"Run {name}."
            decision = run.gov.screen(name, bound.risk, detail)
            if not decision.allowed:
                run.refused += 1
                run.steps.append(f"Refused {name} ({decision.kind}).")
                return refusal(decision.kind or "denied", decision.reason)
            return self._run_skill(run, bound, name, args)
        finally:
            self._release(run)

    def _run_skill(self, run: _Run, bound: BoundSkill, name: str, args: dict[str, Any]) -> Reply:
        with self._lock:
            run.tool_calls += 1
            run.tools.append(name)
            run.steps.append(f"Called {name}.")
        folder = self.output_root / uuid.uuid4().hex
        try:
            context = SkillContext(output_dir=folder, env=self.env, transport=self._skill_transport, resolver=self._resolver)
            try:
                out = bound.skill.run(args, context)
            except SkillError as exc:
                return Reply(200, {"status": "error", "result": str(exc)})
            except Exception as exc:  # a tool error is a tool result, not a crash
                log.warning("skill %s failed unexpectedly (%s)", name, type(exc).__name__)
                return Reply(200, {"status": "error", "result": f"The skill failed unexpectedly ({type(exc).__name__})."})
            budget, files = MAX_INLINE_FILE_BYTES, []
            for info in out.files:
                entry: dict[str, Any] = info.public()
                if info.size <= budget:
                    budget -= info.size
                    entry["content_base64"] = base64.b64encode(info.path.read_bytes()).decode("ascii")
                else:
                    entry["content_omitted"] = "The file is too large to send back in this answer."
                files.append(entry)
            return Reply(200, {"status": "ok", "result": out.text, "files": files})
        finally:
            shutil.rmtree(folder, ignore_errors=True)


# ---------------------------------------------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------------------------------------------

class SkillsServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], runs: SkillRuns, inbound_key: str, *, server_url: str | None = None,
                 max_concurrent: int = 4):
        super().__init__(address, _Handler)
        if not inbound_key:
            raise ValueError("The skills service needs an inbound key.")
        self.runs, self.inbound_key, self.server_url = runs, inbound_key, server_url
        self.slots = threading.BoundedSemaphore(max_concurrent)
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None

    def start_reaper(self, every: float = 5.0) -> None:
        """Finish a quiet run promptly, so its report does not wait for the next call."""
        def loop() -> None:
            while not self._stop.wait(every):
                try:
                    self.runs.close_idle()
                except Exception:
                    log.warning("closing the idle run failed", exc_info=True)
        self._reaper = threading.Thread(target=loop, name="skills-reaper", daemon=True)
        self._reaper.start()

    def shutdown_runs(self) -> None:
        self._stop.set()
        self.runs.close()


class _Handler(BaseHTTPRequestHandler):
    server: SkillsServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # never log bodies or headers
        log.info("%s %s", self.command, self.path.split("?")[0])

    def _send(self, reply: Reply) -> None:
        raw = json.dumps(reply.body).encode("utf-8")
        self.send_response(reply.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in reply.headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _authorised(self) -> bool:
        given = self.headers.get(API_KEY_HEADER, "")
        return hmac.compare_digest(given.encode(), self.server.inbound_key.encode())

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/ping":
            self._send(Reply(200, {"status": "Healthy"}))
        elif path == "/openapi.json" and self.server.server_url:
            if not self._authorised():
                self._send(Reply(401, {"error": "A valid key is required."}))
            else:
                self._send(Reply(200, build_openapi(self.server.runs.definition, self.server.server_url)))
        else:
            self._send(Reply(404, {"error": "Not found."}))

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        if not self._authorised():  # before anything else: a stranger learns nothing, not even which skills exist
            self._send(Reply(401, {"error": "A valid key is required."}))
            return
        name = path.removeprefix("/skills/") if path.startswith("/skills/") else ""
        if not name or "/" in name:
            self._send(Reply(404, {"error": "Not found."}))
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(Reply(411, {"error": "A Content-Length header is required."}))
            return
        if length > MAX_BODY_BYTES:
            self._send(Reply(413, {"error": f"The request is larger than {MAX_BODY_BYTES} bytes."}))
            return
        try:
            args = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            args = None
        if not isinstance(args, dict):
            self._send(Reply(400, {"error": "Send the skill's arguments as one JSON object."}))
            return
        if not self.server.slots.acquire(blocking=False):
            self._send(refusal("limit", "The service is busy with other calls. Try again shortly."))
            return
        try:
            self._send(self.server.runs.call(name, copy.deepcopy(args)))
        except Exception:
            log.exception("skill call failed")
            self._send(refusal("unavailable", "The call could not be completed."))
        finally:
            self.server.slots.release()


def make_skills_server(runs: SkillRuns, host: str, port: int, inbound_key: str, *, server_url: str | None = None,
                       max_concurrent: int = 4) -> SkillsServer:
    return SkillsServer((host, port), runs, inbound_key, server_url=server_url, max_concurrent=max_concurrent)
