"""Shared fakes: a scripted model (both wire formats) and a fake Second Shift. No real network is used."""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx

MODEL_URL = "https://res.services.ai.azure.com"


def definition_dict(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "helper", "name": "Research helper", "description": "Finds things.", "version": "1.2",
        "instructions": "Be brief.",
        "model": {"provider": "foundry_openai", "endpoint_env": "MODEL_URL", "api_key_env": "MODEL_KEY",
                  "deployment": "gpt-test", "max_output_tokens": 500,
                  "input_price_per_million": 2.0, "output_price_per_million": 10.0},
        "skills": [{"name": "fetch_web_page"}],
        "limits": {"max_steps": 5, "max_tool_calls": 3, "max_seconds": 100, "max_cost_dollars": 1.0, "max_input_chars": 200},
        "governance": {"address_env": "SS_URL", "agent_key_env": "SS_KEY"},
    }
    base.update(over)
    return base


ENV = {"MODEL_URL": MODEL_URL + "/openai/v1", "MODEL_KEY": "model-secret-key", "SS_URL": "https://ss.example.com",
       "SS_KEY": "agent-secret-key", "BRAVE_SEARCH_API_KEY": "brave-secret"}


def openai_reply(text: str | None = None, calls: list[tuple[str, Any]] | None = None, usage: tuple[int, int] = (100, 20)) -> dict:
    message: dict[str, Any] = {"role": "assistant", "content": text}
    if calls:
        message["tool_calls"] = [{"id": f"call_{i}", "type": "function",
                                  "function": {"name": n, "arguments": a if isinstance(a, str) else json.dumps(a)}}
                                 for i, (n, a) in enumerate(calls)]
    return {"choices": [{"message": message}], "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]}}


def anthropic_reply(text: str | None = None, calls: list[tuple[str, Any]] | None = None, usage: tuple[int, int] = (100, 20)) -> dict:
    content: list[dict[str, Any]] = [{"type": "text", "text": text}] if text else []
    for i, (n, a) in enumerate(calls or []):
        content.append({"type": "tool_use", "id": f"toolu_{i}", "name": n, "input": a})
    return {"content": content, "usage": {"input_tokens": usage[0], "output_tokens": usage[1]}}


class ScriptedModel:
    """An httpx transport that plays back replies in order and records each request."""

    def __init__(self, replies: list[Any]):
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self.replies.pop(0)
        if isinstance(item, httpx.Response):
            return item
        return httpx.Response(200, json=item)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests]


class FakeSecondShift:
    """The five gateway routes the runtime uses. Set the attributes to script a scenario."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.heartbeat_seconds = 1000.0
        self.start_status = 201
        self.unreachable = False
        self.screens: Callable[[str, dict], dict] = lambda tool, body: {"allowed": True, "rule": "allow", "reason": "within ceilings"}
        self.heartbeats: list[dict] = []  # answers in order; the last repeats
        self.approvals: list[dict] = []  # answers in order; the last repeats
        self.rate_limit_first = 0  # answer this many screens with 429 first
        self.finish_status = 200
        self.report: dict | None = None
        self.screened: list[dict] = []
        self.auth_headers: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectError("down")
        self.auth_headers.add(request.headers.get("authorization", ""))
        path = request.url.path.removeprefix("/api/v1/external")
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        if path == "/runs/start":
            if self.start_status != 201:
                return httpx.Response(self.start_status, json={"detail": "denied: agent is contained pending review"})
            return httpx.Response(201, json={"ok": True, "goal_id": 77, "heartbeat_seconds": self.heartbeat_seconds})
        if path == "/runs/77/heartbeat":
            answer = self.heartbeats.pop(0) if len(self.heartbeats) > 1 else (self.heartbeats[0] if self.heartbeats else {"continue": True, "reason": "ok"})
            return httpx.Response(200, json=answer)
        if path == "/screen":
            if self.rate_limit_first > 0:
                self.rate_limit_first -= 1
                return httpx.Response(429, headers={"Retry-After": "2"}, json={"detail": "rate limit"})
            self.screened.append(body)
            return httpx.Response(200, json=self.screens(body["tool"], body))
        if path.startswith("/approvals/"):
            answer = self.approvals.pop(0) if len(self.approvals) > 1 else self.approvals[0]
            return httpx.Response(200, json=answer)
        if path == "/runs/77/finish":
            self.report = body
            return httpx.Response(self.finish_status, json={"ok": True, "goal_id": 77})
        return httpx.Response(404, json={"detail": "not found"})

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)
