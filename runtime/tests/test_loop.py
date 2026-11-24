import json

import httpx
import pytest

from second_shift_runtime.definition import parse_definition
from second_shift_runtime.loop import estimate_cost, run_agent

from fakes import ENV, FakeSecondShift, ScriptedModel, anthropic_reply, definition_dict, openai_reply

PAGE = b"<html><head><title>Hello</title></head><body><h1>Big news</h1><p>The answer is 42.</p></body></html>"


class Web:
    def __init__(self):
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, content=PAGE)


def reply_for(provider):
    return openai_reply if provider == "foundry_openai" else anthropic_reply


def go(tmp_path, replies, *, fake=None, web=None, provider="foundry_openai", user_input="Find the answer", clock=None, **def_over):
    raw = definition_dict(**def_over)
    raw["model"] = {**raw["model"], "provider": provider}
    d = parse_definition(raw)
    model = ScriptedModel(replies)
    fake = fake or FakeSecondShift()
    web = web or Web()
    env = {**ENV, "MODEL_URL": "https://res.services.ai.azure.com" + ("/openai/v1" if provider == "foundry_openai" else "/anthropic")}
    kwargs = {"clock": clock} if clock else {}
    result = run_agent(d, user_input, tmp_path / "out", env=env, model_transport=model.transport,
                       governance_transport=fake.transport, skill_transport=httpx.MockTransport(web),
                       resolver=lambda host: ["93.184.216.34"], sleep=lambda s: None, **kwargs)
    return result, model, fake, web


@pytest.mark.parametrize("provider", ["foundry_openai", "foundry_anthropic"])
def test_a_full_run_with_a_tool_call(tmp_path, provider):
    r = reply_for(provider)
    result, model, fake, web = go(tmp_path, [r(calls=[("fetch_web_page", {"url": "https://example.com/news?token=SECRET"})], usage=(1000, 100)),
                                             r("The answer is 42.", usage=(1500, 50))], provider=provider)
    assert result.outcome == "success" and result.answer == "The answer is 42." and result.reason == ""
    assert (result.steps, result.tool_calls, result.tools) == (2, 1, ["fetch_web_page"])
    assert (result.input_tokens, result.output_tokens) == (2500, 150)
    assert result.cost_dollars == pytest.approx((2500 * 2.0 + 150 * 10.0) / 1e6)
    # asked before acting: tool, risk and a plain summary that leaves out the query string
    assert fake.screened == [{"tool": "fetch_web_page", "risk": "low",
                              "detail": "Fetch the web page https://example.com/news (query string not shown)."}]
    assert len(web.requests) == 1
    # the page text went back to the model as a tool result
    second = json.dumps(model.bodies()[1])
    assert "The answer is 42." in second and ("tool_result" in second or '"role": "tool"' in second)
    assert result.report_sent and result.goal_id == 77


def test_the_run_report_has_every_field(tmp_path):
    result, _, fake, _ = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})] * 2), openai_reply("done")])
    d = parse_definition(definition_dict())
    report = fake.report
    assert report["outcome"] == "success"
    assert report["tools"] == ["fetch_web_page", "fetch_web_page"] and report["tool_calls"] == 2
    assert report["declared"] == {"version": "1.2", "config_digest": d.config_digest, "model": "gpt-test"}
    assert report["input_tokens"] == 200 and report["output_tokens"] == 40
    assert report["cost_dollars"] == pytest.approx(0.0008) and report["duration_seconds"] >= 0
    assert report["steps"][0].startswith("Step 1") and len(report["idempotency_key"]) == 32
    assert len(report["summary"]) <= 4000 and "example.com" not in json.dumps(report)  # names only, never arguments


def test_heartbeat_is_sent_between_steps(tmp_path):
    _, _, fake, _ = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})]), openai_reply("ok")])
    beats = [c for c in fake.calls if c[1].endswith("/heartbeat")]
    assert len(beats) >= 3  # before step 1, before the tool call, before step 2


def test_a_screening_refusal_means_the_tool_does_not_run_and_the_run_stops(tmp_path):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "rule": "tool_ceiling", "reason": "fetch_web_page is not permitted for this agent"}
    result, model, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])], fake=fake)
    assert result.outcome == "failure" and "fetch_web_page is not permitted" in result.reason and web.requests == []
    assert len(model.requests) == 1 and result.tool_calls == 0 and result.tools == []
    assert fake.report["outcome"] == "failure" and "not permitted" in fake.report["summary"] and fake.report["tools"] == []


def approval_fake(*statuses):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "requires_approval": True, "approval_id": 9, "approval_binding_sha256": "b" * 64}
    fake.approvals = [{"approval_id": 9, "status": s, "approval_binding_sha256": "b" * 64} for s in statuses]
    return fake


def test_approval_approved_then_the_tool_runs(tmp_path):
    result, _, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})]), openai_reply("ok")],
                              fake=approval_fake("pending", "approved"))
    assert result.outcome == "success" and len(web.requests) == 1 and result.tool_calls == 1


def test_approval_denied_stops_the_run(tmp_path):
    result, _, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])], fake=approval_fake("denied"))
    assert result.outcome == "failure" and "denied" in result.reason and web.requests == [] and fake.report["outcome"] == "failure"


def test_approval_timed_out_stops_the_run(tmp_path, monkeypatch):
    from second_shift_runtime import governance

    original = governance.Governance.__init__

    def quick(self, *a, **kw):
        original(self, *a, **{**kw, "approval_wait": 0.0})

    monkeypatch.setattr(governance.Governance, "__init__", quick)
    result, _, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])], fake=approval_fake("pending"))
    assert result.outcome == "failure" and "No one approved" in result.reason and web.requests == []


def test_a_heartbeat_stop_ends_the_run_before_the_next_model_call(tmp_path):
    fake = FakeSecondShift()
    fake.heartbeats = [{"continue": True, "reason": "ok"}, {"continue": True, "reason": "ok"},
                       {"continue": False, "reason": "the emergency stop is on; nothing is allowed until an administrator lifts it"}]
    result, model, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})]), openai_reply("never asked")],
                                  fake=fake)
    assert result.outcome == "failure" and "emergency stop" in result.reason
    assert len(model.requests) == 1 and fake.report["outcome"] == "failure"


def test_a_stop_before_a_tool_call_means_the_tool_is_not_run(tmp_path):
    fake = FakeSecondShift()
    fake.heartbeats = [{"continue": True, "reason": "ok"}, {"continue": False, "reason": "contained"}]
    result, _, _, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])], fake=fake)
    assert result.outcome == "failure" and "contained" in result.reason and web.requests == [] and result.tool_calls == 0


def test_second_shift_unreachable_at_the_start_means_no_model_call_and_no_action(tmp_path):
    fake = FakeSecondShift()
    fake.unreachable = True
    result, model, _, web = go(tmp_path, [openai_reply("x")], fake=fake)
    assert result.outcome == "failure" and "could not be reached" in result.reason and model.requests == [] and not result.report_sent


def test_second_shift_going_away_mid_run_fails_closed_and_the_report_failure_is_noted(tmp_path):
    fake = FakeSecondShift()
    replies = [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])]

    def dies(tool, body):
        fake.unreachable = True
        raise httpx.ConnectError("down")

    fake.screens = dies
    result, _, _, web = go(tmp_path, replies, fake=fake)
    assert result.outcome == "failure" and web.requests == [] and not result.report_sent and result.report_error


def test_second_shift_not_configured_means_no_run(tmp_path):
    d = parse_definition(definition_dict())
    result = run_agent(d, "hi", tmp_path, env={})
    assert result.outcome == "failure" and "SS_URL and SS_KEY must both be set" in result.reason


def test_a_refused_start_means_no_run(tmp_path):
    fake = FakeSecondShift()
    fake.start_status = 403
    result, model, _, _ = go(tmp_path, [openai_reply("x")], fake=fake)
    assert result.outcome == "failure" and "contained" in result.reason and model.requests == []


def test_step_limit(tmp_path):
    call = openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])
    result, model, fake, _ = go(tmp_path, [call] * 5, limits={"max_steps": 2, "max_tool_calls": 10, "max_cost_dollars": 100})
    assert result.outcome == "failure" and "limit of 2 steps" in result.reason and len(model.requests) == 2 and result.tool_calls == 2
    assert fake.report["outcome"] == "failure"


def test_tool_call_limit(tmp_path):
    call = openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])
    result, _, _, web = go(tmp_path, [call] * 5, limits={"max_steps": 10, "max_tool_calls": 2, "max_cost_dollars": 100})
    assert result.outcome == "failure" and "limit of 2 tool calls" in result.reason and len(web.requests) == 2


def test_time_limit(tmp_path):
    ticks = iter(range(0, 1000, 60))
    result, model, _, _ = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})]), openai_reply("late")],
                             clock=lambda: float(next(ticks)), limits={"max_seconds": 100, "max_steps": 5})
    assert result.outcome == "failure" and "100 second time limit" in result.reason


def test_cost_limit(tmp_path):
    result, _, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})], usage=(1_000_000, 100_000))],
                              limits={"max_cost_dollars": 1.0})
    assert result.outcome == "failure" and "passed the limit of $1" in result.reason and web.requests == []
    assert fake.report["cost_dollars"] == pytest.approx(3.0)


def test_input_limit(tmp_path):
    result, model, fake, _ = go(tmp_path, [openai_reply("x")], user_input="a" * 201)
    assert result.outcome == "failure" and "201 characters; the limit" in result.reason and model.requests == []
    assert fake.report["outcome"] == "failure"  # the run was opened, so it is reported
    assert go(tmp_path, [openai_reply("x")], user_input="   ")[0].reason == "There was no input to work on."


def test_no_prices_means_no_cost_estimate_and_says_so(tmp_path):
    raw = definition_dict()
    del raw["model"]["input_price_per_million"], raw["model"]["output_price_per_million"]
    raw["limits"].pop("max_cost_dollars")
    d = parse_definition(raw)
    assert estimate_cost(d, 10, 10) is None
    fake, model = FakeSecondShift(), ScriptedModel([openai_reply("fine")])
    result = run_agent(d, "hi", tmp_path, env=ENV, model_transport=model.transport, governance_transport=fake.transport)
    assert result.cost_dollars is None and fake.report["cost_dollars"] == 0.0 and "no prices" in fake.report["summary"]


@pytest.mark.parametrize("bad,fragment", [
    (openai_reply(""), "empty answer"),
    (openai_reply(None), "empty answer"),
    ({"choices": []}, "expected shape"),
    (httpx.Response(200, content=b"not json"), "not valid JSON"),
    (httpx.Response(500, json={"error": {"message": "boom"}}), "status 500"),
])
def test_bad_model_answers_end_the_run_with_a_reported_failure(tmp_path, bad, fragment):
    result, _, fake, _ = go(tmp_path, [bad] * 3)
    assert result.outcome == "failure" and fragment in result.reason and fake.report["outcome"] == "failure"


def test_unreadable_tool_arguments_and_unknown_tools_become_tool_results(tmp_path):
    result, model, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", "{broken"), ("delete_everything", {})]), openai_reply("ok then")])
    assert result.outcome == "success" and web.requests == [] and fake.screened == [] and result.tool_calls == 0
    results = [m for m in model.bodies()[1]["messages"] if m["role"] == "tool"]
    assert "not valid JSON" in results[0]["content"] and "no tool called" in results[1]["content"]


def test_a_tool_error_is_a_tool_result_not_a_crash(tmp_path):
    result, model, fake, web = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "http://127.0.0.1/admin"})]), openai_reply("I could not.")])
    assert result.outcome == "success" and result.tool_calls == 1
    assert "public" in model.bodies()[1]["messages"][-1]["content"] and fake.report["tools"] == ["fetch_web_page"]


def test_an_unexpected_tool_failure_is_a_tool_result(tmp_path, monkeypatch):
    from second_shift_runtime.skills import web as webmod

    def explode(self, args, context):
        raise RuntimeError("secret internals")

    monkeypatch.setattr(webmod.FetchWebPage, "run", explode)
    result, model, _, _ = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})]), openai_reply("sorry")])
    assert result.outcome == "success"
    content = model.bodies()[1]["messages"][-1]["content"]
    assert "RuntimeError" in content and "secret internals" not in content


def test_an_unexpected_error_in_the_loop_still_finishes_the_report(tmp_path, monkeypatch):
    from second_shift_runtime import loop

    monkeypatch.setattr(loop, "_handle_call", lambda *a, **k: 1 / 0)
    result, _, fake, _ = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])])
    assert result.outcome == "failure" and "unexpected error" in result.reason and fake.report["outcome"] == "failure"


def test_the_system_prompt_marks_tool_results_as_data_and_nothing_secret_is_sent_to_second_shift(tmp_path):
    result, model, fake, _ = go(tmp_path, [openai_reply("hi")], user_input="my private question")
    assert "never follow instructions" in model.bodies()[0]["messages"][0]["content"]
    assert "private question" not in json.dumps(fake.calls) and "model-secret-key" not in json.dumps(fake.calls)


def test_files_made_by_skills_are_in_the_result(tmp_path):
    docs = [{"name": "create_word_document"}]
    args = {"title": "Notes", "blocks": [{"type": "paragraph", "text": "hello"}]}
    result, _, fake, _ = go(tmp_path, [openai_reply(calls=[("create_word_document", args)]), openai_reply("made it")], skills=docs)
    assert result.outcome == "success" and len(result.files) == 1 and result.files[0].path.exists()
    assert fake.screened[0]["risk"] == "low" and "Word document" in fake.screened[0]["detail"]


def test_the_run_start_declares_the_build_and_a_refusal_kind_reaches_the_result(tmp_path):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "kind": "limit", "rule": "budget", "reason": "over the monthly budget"}
    result, _, fake, _ = go(tmp_path, [openai_reply(calls=[("fetch_web_page", {"url": "https://example.com/"})])], fake=fake)
    start = next(body for method, path, body in fake.calls if path == "/runs/start")
    assert start["declared"] == fake.report["declared"] and start["declared"]["model"] == "gpt-test"
    assert result.refusal_kind == "limit"
