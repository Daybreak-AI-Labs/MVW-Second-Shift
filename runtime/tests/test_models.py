import json

import httpx
import pytest

from second_shift_runtime.definition import parse_definition
from second_shift_runtime.models import (
    FoundryAnthropic,
    FoundryOpenAI,
    Message,
    ModelError,
    ToolCall,
    ToolSpec,
    build_model,
)

from fakes import ENV, ScriptedModel, anthropic_reply, definition_dict, openai_reply

TOOLS = [ToolSpec("fetch_web_page", "Fetch.", {"type": "object", "properties": {"url": {"type": "string"}}})]


def settings(provider):
    raw = definition_dict()
    raw["model"]["provider"] = provider
    return parse_definition(raw).model


def client(provider, replies, **env):
    fake = ScriptedModel(replies)
    path = "/openai/v1" if provider == "foundry_openai" else "/anthropic"
    environ = {**ENV, "MODEL_URL": "https://res.services.ai.azure.com" + path, **env}
    return build_model(settings(provider), environ, transport=fake.transport, sleep=lambda s: None), fake


def test_openai_request_shape_and_reply():
    model, fake = client("foundry_openai", [openai_reply(calls=[("fetch_web_page", {"url": "https://a.example/"})], usage=(11, 7))])
    history = [Message("user", "hi")]
    reply = model.complete("Be brief.", history, TOOLS)
    req = fake.requests[0]
    assert str(req.url) == "https://res.services.ai.azure.com/openai/v1/chat/completions"
    assert req.headers["api-key"] == "model-secret-key" and "authorization" not in req.headers
    body = fake.bodies()[0]
    assert body["model"] == "gpt-test" and body["max_completion_tokens"] == 500
    assert body["messages"][0] == {"role": "system", "content": "Be brief."}
    assert body["tools"][0]["function"]["name"] == "fetch_web_page"
    assert reply.tool_calls == [ToolCall("call_0", "fetch_web_page", {"url": "https://a.example/"})]
    assert (reply.input_tokens, reply.output_tokens) == (11, 7)


def test_openai_sends_tool_results_back_as_tool_messages():
    model, fake = client("foundry_openai", [openai_reply("done")])
    call = ToolCall("call_0", "fetch_web_page", {"url": "u"})
    model.complete("s", [Message("user", "q"), Message("assistant", "", [call]), Message("tool", "page text", tool_call_id="call_0")], TOOLS)
    wire = fake.bodies()[0]["messages"]
    assert wire[2]["tool_calls"][0]["function"] == {"name": "fetch_web_page", "arguments": json.dumps({"url": "u"})}
    assert wire[3] == {"role": "tool", "tool_call_id": "call_0", "content": "page text"}


def test_anthropic_request_shape_and_reply():
    model, fake = client("foundry_anthropic", [anthropic_reply("hello", [("fetch_web_page", {"url": "u"})], usage=(5, 3))])
    reply = model.complete("Be brief.", [Message("user", "hi")], TOOLS)
    req = fake.requests[0]
    assert str(req.url) == "https://res.services.ai.azure.com/anthropic/v1/messages"
    assert req.headers["x-api-key"] == "model-secret-key" and req.headers["anthropic-version"] == "2023-06-01"
    body = fake.bodies()[0]
    assert body["system"] == "Be brief." and body["max_tokens"] == 500 and body["tools"][0]["input_schema"]["type"] == "object"
    assert reply.text == "hello" and reply.tool_calls[0].arguments == {"url": "u"}
    assert (reply.input_tokens, reply.output_tokens) == (5, 3)


def test_anthropic_groups_the_results_of_one_turn_into_one_user_message():
    model, fake = client("foundry_anthropic", [anthropic_reply("ok")])
    calls = [ToolCall("t0", "a", {}), ToolCall("t1", "b", {})]
    model.complete("s", [Message("user", "q"), Message("assistant", "", calls),
                         Message("tool", "r0", tool_call_id="t0"), Message("tool", "r1", tool_call_id="t1", is_error=True)], TOOLS)
    wire = fake.bodies()[0]["messages"]
    assert len(wire) == 3 and wire[2]["role"] == "user"
    assert [b["tool_use_id"] for b in wire[2]["content"]] == ["t0", "t1"] and wire[2]["content"][1]["is_error"] is True


@pytest.mark.parametrize("provider,bad", [
    ("foundry_openai", {"choices": []}),
    ("foundry_openai", {"nothing": 1}),
    ("foundry_openai", {"choices": [{"message": {"tool_calls": [{"id": "1"}]}}]}),
    ("foundry_anthropic", {"content": "text"}),
    ("foundry_anthropic", {"nothing": 1}),
])
def test_unexpected_answer_shapes_are_model_errors(provider, bad):
    model, _ = client(provider, [bad])
    with pytest.raises(ModelError, match="expected shape"):
        model.complete("s", [Message("user", "q")], TOOLS)


def test_unparseable_answers_and_unreadable_tool_arguments():
    model, _ = client("foundry_openai", [httpx.Response(200, content=b"<html>"), httpx.Response(200, json=[1])])
    with pytest.raises(ModelError, match="not valid JSON"):
        model.complete("s", [Message("user", "q")], TOOLS)
    with pytest.raises(ModelError, match="unexpected shape"):
        model.complete("s", [Message("user", "q")], TOOLS)
    model, _ = client("foundry_openai", [openai_reply(calls=[("fetch_web_page", "{broken")]), openai_reply(calls=[("x", "[1]")])])
    first = model.complete("s", [Message("user", "q")], TOOLS).tool_calls[0]
    assert first.arguments == {} and "not valid JSON" in first.error
    assert "not a JSON object" in model.complete("s", [Message("user", "q")], TOOLS).tool_calls[0].error


def test_http_errors_are_plain_and_never_contain_the_key_or_prompt():
    secret_prompt = "PRIVATE PROMPT TEXT"
    for status, fragment in [(401, "refused the key"), (404, "did not find"), (500, "status 500")]:
        model, _ = client("foundry_openai", [httpx.Response(status, json={"error": {"message": "bad thing"}})] * 3)
        with pytest.raises(ModelError, match=fragment) as err:
            model.complete("s", [Message("user", secret_prompt)], TOOLS)
        assert "model-secret-key" not in str(err.value) and secret_prompt not in str(err.value)


def test_a_busy_service_is_retried_with_retry_after_and_then_given_up_on():
    waits = []
    fake = ScriptedModel([httpx.Response(429, headers={"Retry-After": "3"}, json={}), openai_reply("fine")])
    model = build_model(settings("foundry_openai"), ENV, transport=fake.transport, sleep=waits.append)
    assert model.complete("s", [Message("user", "q")], []).text == "fine" and waits == [3.0]
    fake = ScriptedModel([httpx.Response(429, headers={"Retry-After": "3"}, json={})] * 5)
    model = build_model(settings("foundry_openai"), ENV, transport=fake.transport, sleep=waits.append)
    with pytest.raises(ModelError, match="status 429"):
        model.complete("s", [Message("user", "q")], [])
    assert len(fake.requests) == 3
    fake = ScriptedModel([httpx.Response(429, headers={"Retry-After": "900"}, json={})])
    model = build_model(settings("foundry_openai"), ENV, transport=fake.transport, sleep=waits.append)
    with pytest.raises(ModelError):
        model.complete("s", [Message("user", "q")], [])
    assert len(fake.requests) == 1


def test_network_failures_timeouts_and_oversized_answers(monkeypatch):
    def boom(request):
        raise httpx.ConnectError("no route")

    def slow(request):
        raise httpx.ReadTimeout("slow")

    for handler, fragment in [(boom, "could not be reached"), (slow, "too long")]:
        model = build_model(settings("foundry_openai"), ENV, transport=httpx.MockTransport(handler))
        with pytest.raises(ModelError, match=fragment):
            model.complete("s", [Message("user", "q")], [])
    monkeypatch.setattr("second_shift_runtime.models.MAX_RESPONSE_BYTES", 100)
    model, _ = client("foundry_openai", [openai_reply("x" * 500)])
    with pytest.raises(ModelError, match="larger than the allowed size"):
        model.complete("s", [Message("user", "q")], [])


def test_setup_problems_are_explained():
    with pytest.raises(ModelError, match="MODEL_KEY is empty"):
        build_model(settings("foundry_openai"), {**ENV, "MODEL_KEY": ""})
    with pytest.raises(ModelError, match="MODEL_URL is empty"):
        build_model(settings("foundry_openai"), {**ENV, "MODEL_URL": ""})
    with pytest.raises(ModelError, match="must start with https"):
        build_model(settings("foundry_openai"), {**ENV, "MODEL_URL": "http://evil.example.com/v1"})
    assert isinstance(build_model(settings("foundry_openai"), {**ENV, "MODEL_URL": "http://localhost:9/v1"}), FoundryOpenAI)
    assert isinstance(build_model(settings("foundry_anthropic"), ENV), FoundryAnthropic)
