"""``serve``: the HTTP contract of an Amazon Bedrock AgentCore container, usable unchanged in Azure Container Apps.

AgentCore Runtime requires, on 0.0.0.0:8080 (arm64 container image):
``GET /ping`` answering 200 with ``{"status": "Healthy"}`` (or ``"HealthyBusy"``), and ``POST /invocations`` taking JSON
(for example ``{"prompt": "..."}``) and answering JSON such as ``{"response": "...", "status": "success"}``.
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-http-protocol-contract.html

Standard library only. Each invocation is one governed run with its own output folder.
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .definition import AgentDefinition
from .loop import RunResult, run_agent

log = logging.getLogger("second_shift_runtime.server")

MAX_BODY_BYTES = 1_000_000
MAX_INLINE_FILE_BYTES = 8_000_000  # files come back inside the answer because a container's disk is not reachable

Runner = Callable[[str, Path], RunResult]


def definition_runner(definition: AgentDefinition) -> Runner:
    return lambda prompt, output_dir: run_agent(definition, prompt, output_dir)


def result_body(result: RunResult) -> dict[str, Any]:
    budget = MAX_INLINE_FILE_BYTES
    files = []
    for info in result.files:
        entry: dict[str, Any] = info.public()
        if info.size <= budget:
            budget -= info.size
            entry["content_base64"] = base64.b64encode(info.path.read_bytes()).decode("ascii")
        else:
            entry["content_omitted"] = "The files in this answer are too large to send back together."
        files.append(entry)
    return {
        "response": result.answer or result.reason,
        "status": result.outcome,
        "reason": result.reason,
        "files": files,
        "usage": {"steps": result.steps, "tool_calls": result.tool_calls, "input_tokens": result.input_tokens,
                  "output_tokens": result.output_tokens, "estimated_cost_dollars": result.cost_dollars},
        "report_sent": result.report_sent,
    }


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], runner: Runner, output_root: Path, *, inbound_key: str | None = None,
                 max_concurrent: int = 4):
        super().__init__(address, _Handler)
        self.runner, self.output_root, self.inbound_key = runner, output_root, inbound_key
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._active = 0
        self._lock = threading.Lock()
        self._status, self._changed = "Healthy", int(time.time())

    def acquire(self) -> bool:
        if not self._slots.acquire(blocking=False):
            return False
        self._set_active(+1)
        return True

    def release(self) -> None:
        self._set_active(-1)
        self._slots.release()

    def _set_active(self, delta: int) -> None:
        with self._lock:
            self._active += delta
            status = "HealthyBusy" if self._active else "Healthy"
            if status != self._status:  # the time moves only when the status does, as AgentCore asks
                self._status, self._changed = status, int(time.time())

    def ping(self) -> dict[str, Any]:
        with self._lock:
            return {"status": self._status, "time_of_last_update": self._changed}


class _Handler(BaseHTTPRequestHandler):
    server: AgentServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # never log bodies or headers
        log.info("%s %s", self.command, self.path.split("?")[0])

    def _send(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path.split("?")[0] == "/ping":
            self._send(200, self.server.ping())
        else:
            self._send(404, {"error": "Not found."})

    def do_POST(self) -> None:
        if self.path.split("?")[0] != "/invocations":
            self._send(404, {"error": "Not found."})
            return
        key = self.server.inbound_key
        if key is not None:
            given = self.headers.get("Authorization", "")
            if not hmac.compare_digest(given.encode(), f"Bearer {key}".encode()):
                self._send(401, {"error": "A valid bearer key is required."}, {"WWW-Authenticate": "Bearer"})
                return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(411, {"error": "A Content-Length header is required."})
            return
        if length > MAX_BODY_BYTES:
            self._send(413, {"error": f"The request is larger than {MAX_BODY_BYTES} bytes."})
            return
        try:
            body = json.loads(self.rfile.read(length))
            prompt = body.get("prompt", body.get("input")) if isinstance(body, dict) else None
        except ValueError:
            prompt = None
        if not isinstance(prompt, str) or not prompt.strip():
            self._send(400, {"error": 'Send a JSON object with the task as text in "prompt".'})
            return
        if not self.server.acquire():
            self._send(429, {"error": "The agent is busy with other runs. Try again shortly."}, {"Retry-After": "5"})
            return
        try:
            output_dir = self.server.output_root / uuid.uuid4().hex
            result = self.server.runner(prompt, output_dir)
            self._send(200, result_body(result))
        except Exception:
            log.exception("invocation failed")
            self._send(500, {"error": "The run could not be completed."})
        finally:
            self.server.release()


def make_server(runner: Runner, host: str, port: int, output_root: Path, *, inbound_key: str | None = None,
                max_concurrent: int = 4) -> AgentServer:
    return AgentServer((host, port), runner, output_root, inbound_key=inbound_key, max_concurrent=max_concurrent)
