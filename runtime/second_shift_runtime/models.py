"""Model clients for models served through a Microsoft Foundry resource, called with an API key.

Both clients take the same conversation and give back the same ``ModelReply``.

* ``foundry_openai``: the OpenAI-compatible v1 API. ``POST {endpoint}/chat/completions`` where the endpoint is
  ``https://<resource>.openai.azure.com/openai/v1`` (or ``.../services.ai.azure.com/openai/v1``), key in the
  ``api-key`` header, deployment name in ``model``.
  https://learn.microsoft.com/azure/foundry/openai/api-version-lifecycle#code-changes
  https://learn.microsoft.com/rest/api/microsoft-foundry/azureopenai/chat#create-chat-completion
  Request and reply bodies follow the OpenAI chat completions format (tools, tool_calls, usage).
* ``foundry_anthropic``: Claude's Messages API. ``POST {endpoint}/v1/messages`` where the endpoint is
  ``https://<resource>.services.ai.azure.com/anthropic``, key in ``x-api-key``, ``anthropic-version: 2023-06-01``.
  https://learn.microsoft.com/azure/foundry/foundry-models/how-to/use-foundry-models-claude
  https://learn.microsoft.com/azure/foundry/foundry-models/concepts/claude-models
  Body shape (system, messages, tools with input_schema, tool_use / tool_result blocks) is the Anthropic Messages API.

A key and a prompt are never logged and never put in an error message.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from .definition import ModelSettings

MAX_RESPONSE_BYTES = 4_000_000
DEFAULT_TIMEOUT = 120.0
RETRY_STATUSES = (429, 502, 503, 504)
MAX_RETRIES = 2
MAX_RETRY_WAIT = 30.0


class ModelError(Exception):
    """The model could not give a usable answer. The message is plain and safe to show."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    error: str | None = None  # set when the model's arguments were not a JSON object


@dataclass
class ModelReply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class Message:
    """One turn in the common conversation format.

    role "user" and "assistant" carry ``text`` (and the assistant's ``tool_calls``);
    role "tool" carries the result of one call: ``tool_call_id``, ``text`` and ``is_error``."""

    role: str
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str = ""
    is_error: bool = False


class ModelClient:
    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec], *, timeout: float | None = None) -> ModelReply:
        raise NotImplementedError


def _endpoint(value: str, name: str) -> str:
    parts = urlsplit(value.strip())
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise ModelError(f"The model address in {name} must start with https://.")
    if not parts.hostname or parts.username or parts.password:
        raise ModelError(f"The model address in {name} is not a plain web address.")
    return value.strip().rstrip("/")


class _HttpModel(ModelClient):
    def __init__(self, base_url: str, api_key: str, settings: ModelSettings, *, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self._base = base_url
        self._key = api_key
        self._settings = settings
        self._client = httpx.Client(transport=transport, timeout=DEFAULT_TIMEOUT, follow_redirects=False, trust_env=False)
        self._sleep = sleep

    def _post(self, path: str, headers: dict[str, str], body: dict[str, Any], timeout: float | None) -> dict[str, Any]:
        url = self._base + path
        payload = json.dumps(body).encode("utf-8")
        for attempt in range(MAX_RETRIES + 1):
            try:
                request = self._client.build_request("POST", url, content=payload,
                                                     headers={**headers, "content-type": "application/json"},
                                                     timeout=timeout or DEFAULT_TIMEOUT)
                response = self._client.send(request, stream=True)
            except httpx.TimeoutException as exc:
                raise ModelError("The model took too long to answer.") from exc
            except httpx.HTTPError as exc:
                raise ModelError("The model service could not be reached.") from exc
            try:
                if response.status_code in RETRY_STATUSES and attempt < MAX_RETRIES:
                    wait = _retry_after(response.headers.get("retry-after"), default=1.0 + attempt)
                    if wait <= MAX_RETRY_WAIT:
                        response.close()
                        self._sleep(wait)
                        continue
                raw = self._read(response)
                if response.status_code != 200:
                    raise ModelError(_status_message(response.status_code, raw))
                try:
                    data = json.loads(raw)
                except ValueError as exc:
                    raise ModelError("The model sent an answer that is not valid JSON.") from exc
                if not isinstance(data, dict):
                    raise ModelError("The model sent an answer in an unexpected shape.")
                return data
            finally:
                response.close()
        raise ModelError("The model service kept refusing; try again later.")  # pragma: no cover

    @staticmethod
    def _read(response: httpx.Response) -> bytes:
        body = b""
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_RESPONSE_BYTES:
                raise ModelError("The model's answer was larger than the allowed size.")
        return body


def _retry_after(value: str | None, default: float) -> float:
    try:
        return max(0.0, float(value)) if value else default
    except ValueError:
        return default


def _status_message(status: int, raw: bytes) -> str:
    detail = ""
    try:
        data = json.loads(raw)
        error = data.get("error") if isinstance(data, dict) else None
        text = error.get("message") if isinstance(error, dict) else error
        if isinstance(text, str):
            detail = " " + " ".join(text.split())[:200]
    except ValueError:
        pass
    if status in (401, 403):
        return f"The model service refused the key (status {status}). Check the key and the deployment name.{detail}"
    if status == 404:
        return f"The model service did not find that address or deployment (status 404). Check the address and deployment name.{detail}"
    return f"The model service answered with status {status}.{detail}"


def _tokens(usage: Any, *names: str) -> int:
    if isinstance(usage, dict):
        for name in names:
            value = usage.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
    return 0


def _arguments(raw: Any) -> tuple[dict[str, Any], str | None]:
    if isinstance(raw, dict):
        return raw, None
    if raw in ("", None):
        return {}, None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}, "The tool arguments were not valid JSON."
    if not isinstance(value, dict):
        return {}, "The tool arguments were not a JSON object."
    return value, None


class FoundryOpenAI(_HttpModel):
    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec], *, timeout: float | None = None) -> ModelReply:
        wire: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m.role == "tool":
                wire.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.text})
            elif m.role == "assistant":
                entry: dict[str, Any] = {"role": "assistant", "content": m.text or None}
                if m.tool_calls:
                    entry["tool_calls"] = [{"id": c.id, "type": "function",
                                            "function": {"name": c.name, "arguments": json.dumps(c.arguments)}} for c in m.tool_calls]
                wire.append(entry)
            else:
                wire.append({"role": "user", "content": m.text})
        body: dict[str, Any] = {"model": self._settings.deployment, "messages": wire,
                                "max_completion_tokens": self._settings.max_output_tokens}
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.schema}}
                             for t in tools]
        data = self._post("/chat/completions", {"api-key": self._key}, body, timeout)
        try:
            choices = data["choices"]
            message = choices[0]["message"]
            content = message.get("content")
            text = content if isinstance(content, str) else ""
            calls = []
            for raw in message.get("tool_calls") or []:
                function = raw["function"]
                args, error = _arguments(function.get("arguments"))
                calls.append(ToolCall(str(raw["id"]), str(function["name"]), args, error))
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ModelError("The model's answer did not have the expected shape.") from exc
        usage = data.get("usage")
        return ModelReply(text, calls, _tokens(usage, "prompt_tokens"), _tokens(usage, "completion_tokens"))


class FoundryAnthropic(_HttpModel):
    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec], *, timeout: float | None = None) -> ModelReply:
        wire: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "tool":
                block = {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.text, "is_error": m.is_error}
                if wire and wire[-1]["role"] == "user" and isinstance(wire[-1]["content"], list):
                    wire[-1]["content"].append(block)  # all results of one turn go in one user message
                else:
                    wire.append({"role": "user", "content": [block]})
            elif m.role == "assistant":
                content: list[dict[str, Any]] = [{"type": "text", "text": m.text}] if m.text else []
                content += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments} for c in m.tool_calls]
                wire.append({"role": "assistant", "content": content})
            else:
                wire.append({"role": "user", "content": m.text})
        body: dict[str, Any] = {"model": self._settings.deployment, "max_tokens": self._settings.max_output_tokens,
                                "system": system, "messages": wire}
        if tools:
            body["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.schema} for t in tools]
        data = self._post("/v1/messages", {"x-api-key": self._key, "anthropic-version": "2023-06-01"}, body, timeout)
        try:
            texts, calls = [], []
            for block in data["content"]:
                if block["type"] == "text":
                    texts.append(str(block["text"]))
                elif block["type"] == "tool_use":
                    args, error = _arguments(block.get("input"))
                    calls.append(ToolCall(str(block["id"]), str(block["name"]), args, error))
        except (KeyError, TypeError) as exc:
            raise ModelError("The model's answer did not have the expected shape.") from exc
        usage = data.get("usage")
        return ModelReply("".join(texts), calls, _tokens(usage, "input_tokens"), _tokens(usage, "output_tokens"))


def build_model(settings: ModelSettings, env: Mapping[str, str], *, transport: httpx.BaseTransport | None = None,
                sleep: Callable[[float], None] = time.sleep) -> ModelClient:
    """Make the client a definition asks for, reading the endpoint and key from the named variables."""
    endpoint = env.get(settings.endpoint_env, "")
    key = env.get(settings.api_key_env, "")
    if not endpoint:
        raise ModelError(f"The model address is not set: the environment variable {settings.endpoint_env} is empty.")
    if not key:
        raise ModelError(f"The model key is not set: the environment variable {settings.api_key_env} is empty.")
    cls = FoundryOpenAI if settings.provider == "foundry_openai" else FoundryAnthropic
    return cls(_endpoint(endpoint, settings.endpoint_env), key, settings, transport=transport, sleep=sleep)
