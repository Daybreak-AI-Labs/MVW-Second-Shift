"""The skills service: what Foundry's OpenAPI tool calls. Every call is screened with Second Shift first."""
import base64
import json
import threading

import httpx
import pytest

from second_shift_runtime.definition import parse_definition
from second_shift_runtime.governance import Governance
from second_shift_runtime.skills_service import (
    API_KEY_HEADER,
    SkillRuns,
    build_openapi,
    check_foundry_openapi,
    make_skills_server,
    to_openapi30,
)

from fakes import ENV, FakeSecondShift, definition_dict

PAGE = b"<html><head><title>Hello</title></head><body><p>The answer is 42.</p></body></html>"
KEY = "inbound-secret-key-1"  # pragma: allowlist secret
ALL = [{"name": n} for n in ("fetch_web_page", "web_search", "create_word_document", "create_presentation", "create_spreadsheet")]


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_runs(tmp_path, fake=None, clock=None, skills=None, limits=None, **kw):
    raw = definition_dict(skills=skills or [{"name": "fetch_web_page"}, {"name": "create_word_document"}])
    if limits:
        raw["limits"] = {**raw["limits"], **limits}
    d = parse_definition(raw)
    fake = fake or FakeSecondShift()
    clock = clock or Clock()
    built = []

    def factory():
        gov = Governance("https://ss.example.com", "agent-secret-key", transport=fake.transport, sleep=lambda s: None,
                         clock=clock, approval_wait=30.0, poll_interval=3.0)
        built.append(gov)
        return gov

    web = []

    def page(request):
        web.append(request)
        return httpx.Response(200, headers={"content-type": "text/html"}, content=PAGE)

    runs = SkillRuns(d, tmp_path / "out", env=ENV, governance_factory=factory, clock=clock,
                     skill_transport=httpx.MockTransport(page), resolver=lambda host: ["93.184.216.34"], **kw)
    return runs, fake, clock, web, built


FETCH = {"url": "https://example.com/"}


# --- the OpenAPI file --------------------------------------------------------------------------------------

def spec_for(skills):
    return build_openapi(parse_definition(definition_dict(skills=skills)), "https://skills.example.net")


def test_the_openapi_file_meets_foundrys_documented_rules_for_every_skill():
    spec = spec_for(ALL)
    assert check_foundry_openapi(spec) == []
    assert spec["openapi"] == "3.0.3" and spec["servers"] == [{"url": "https://skills.example.net"}]
    ids = {op["post"]["operationId"] for op in spec["paths"].values()}
    assert ids == {s["name"] for s in ALL}
    scheme = spec["components"]["securitySchemes"]
    assert list(scheme.values()) == [{"type": "apiKey", "in": "header", "name": API_KEY_HEADER}]
    for item in spec["paths"].values():
        assert list(item["post"]["requestBody"]["content"]) == ["application/json"]


def test_the_spreadsheet_schema_has_no_list_of_types_which_openapi_30_does_not_allow():
    spec = spec_for([{"name": "create_spreadsheet"}])
    text = json.dumps(spec)
    assert '"type": ["' not in text and "nullable" in text and "anyOf" in text


def test_to_openapi30_keeps_a_property_that_is_named_like_a_keyword():
    out = to_openapi30({"type": "object", "properties": {"const": {"type": "string"}}, "$schema": "x"})
    assert "const" in out["properties"] and "$schema" not in out


@pytest.mark.parametrize("change,fragment", [
    (lambda s: s["paths"]["/skills/fetch_web_page"]["post"].update(operationId="fetch web page"), "operationId"),
    (lambda s: s["paths"]["/skills/fetch_web_page"]["post"].update(operationId="fetch2"), "operationId"),
    (lambda s: s["paths"]["/skills/fetch_web_page"]["post"]["requestBody"]["content"].update({"text/plain": {}}), "text/plain"),
    (lambda s: s["components"]["securitySchemes"].update(second={"type": "apiKey", "in": "header", "name": "x-other"}), "exactly one"),
    (lambda s: s["components"].update(securitySchemes={}), "exactly one"),
    (lambda s: s.update(security=[]), "security must list"),
    (lambda s: s.update(servers=[{"url": "http://x"}]), "https"),
    (lambda s: s.update(openapi="2.0"), "3.0"),
    (lambda s: s["paths"]["/skills/fetch_web_page"]["post"]["requestBody"]["content"]["application/json"]["schema"].update(type=["string", "null"]), "list of types"),
])
def test_the_checker_catches_what_foundry_would_refuse(change, fragment):
    spec = spec_for([{"name": "fetch_web_page"}])
    change(spec)
    assert any(fragment in p for p in check_foundry_openapi(spec)), check_foundry_openapi(spec)


def test_the_file_never_holds_a_key_and_needs_an_https_address():
    assert KEY not in json.dumps(spec_for(ALL))
    with pytest.raises(ValueError, match="https"):
        build_openapi(parse_definition(definition_dict()), "http://skills.example.net")
    with pytest.raises(ValueError, match="no skills"):
        build_openapi(parse_definition(definition_dict(skills=[])), "https://skills.example.net")


# --- every call is screened first --------------------------------------------------------------------------

def test_a_call_is_screened_before_the_skill_runs_and_then_runs(tmp_path):
    runs, fake, _, web, _ = make_runs(tmp_path)
    order = []
    fake.screens = lambda tool, body: (order.append(("screen", len(web))), {"allowed": True, "rule": "allow", "reason": "ok"})[1]
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.status == 200 and reply.body["status"] == "ok" and "42" in reply.body["result"]
    assert order == [("screen", 0)] and len(web) == 1  # the page was fetched only after the screen
    assert fake.screened[0]["tool"] == "fetch_web_page" and fake.screened[0]["risk"] == "low"
    assert "example.com" in fake.screened[0]["detail"] and fake.auth_headers == {"Bearer agent-secret-key"}


def test_a_refused_call_does_not_run_the_skill_and_names_its_kind(tmp_path):
    runs, fake, _, web, _ = make_runs(tmp_path)
    fake.screens = lambda tool, body: {"allowed": False, "rule": "tool", "kind": "denied", "reason": "not permitted"}
    reply = runs.call("fetch_web_page", FETCH)
    assert (reply.status, reply.body["kind"], reply.body["retry_later"]) == (403, "denied", False)
    assert reply.body["reason"] == "not permitted" and web == []


@pytest.mark.parametrize("kind,status,later", [("halted", 503, False), ("contained", 403, False), ("limit", 429, True),
                                               ("unavailable", 503, True)])
def test_each_refusal_kind_has_its_own_status_and_says_whether_to_retry(tmp_path, kind, status, later):
    runs, fake, _, web, _ = make_runs(tmp_path)
    fake.screens = lambda tool, body: {"allowed": False, "kind": kind, "reason": "no"}
    reply = runs.call("fetch_web_page", FETCH)
    assert (reply.status, reply.body["kind"], reply.body["retry_later"]) == (status, kind, later) and web == []
    assert ("Retry-After" in reply.headers) is later


def test_second_shift_unreachable_means_the_skill_does_not_run(tmp_path):
    runs, fake, _, web, _ = make_runs(tmp_path)
    fake.unreachable = True
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.status == 503 and reply.body["kind"] == "unavailable" and web == []


def test_not_set_up_means_no_run_and_no_skill(tmp_path):
    d = parse_definition(definition_dict())
    runs = SkillRuns(d, tmp_path, env={}, skill_transport=httpx.MockTransport(lambda r: pytest.fail("no network")))
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.body["kind"] == "unavailable" and "SS_KEY" in reply.body["reason"]


# --- approval ----------------------------------------------------------------------------------------------

def approval_fake(*statuses):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "requires_approval": True, "approval_id": 9,
                                       "approval_binding_sha256": "b" * 64, "kind": "approval_required"}
    fake.approvals = [{"approval_id": 9, "status": s, "approval_binding_sha256": "b" * 64} for s in statuses]
    return fake


def test_the_call_waits_for_a_person_and_runs_only_once_approved(tmp_path):
    runs, fake, _, web, _ = make_runs(tmp_path, fake=approval_fake("pending", "pending", "approved"))
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.status == 200 and len(web) == 1
    assert sum(1 for c in fake.calls if c[1].startswith("/approvals/")) == 3


def test_a_denied_approval_does_not_run_and_a_wait_that_runs_out_says_try_later(tmp_path):
    runs, _, _, web, _ = make_runs(tmp_path, fake=approval_fake("denied"))
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.body["kind"] == "denied" and web == []
    clock = Clock()
    runs, fake, _, web, _ = make_runs(tmp_path, fake=approval_fake("pending"), clock=clock)
    # each poll sleeps (here: advances nothing), so move the clock on every poll
    original = fake.__call__

    def ticking(request):
        clock.now += 10
        return original(request)

    fake.__call__ = ticking
    runs._factory = lambda: Governance("https://ss.example.com", "k", transport=httpx.MockTransport(ticking), sleep=lambda s: None,
                                       clock=clock, approval_wait=30.0, poll_interval=3.0)
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.status == 408 and reply.body["kind"] == "approval_required" and reply.body["retry_later"] and web == []


# --- the emergency stop --------------------------------------------------------------------------------------

def test_the_emergency_stop_refuses_the_next_call_even_when_a_run_is_open(tmp_path):
    runs, fake, _, web, built = make_runs(tmp_path)
    assert runs.call("fetch_web_page", FETCH).status == 200
    stop = "the emergency stop is on; nothing is allowed until an administrator lifts it"
    fake.heartbeats = [{"continue": False, "reason": stop}]
    assert built[0].beat() is False  # the heartbeat says stop
    original = fake.__call__

    def stopped(request):
        if request.url.path.endswith("/runs/start"):
            return httpx.Response(403, json={"detail": "denied: " + stop})
        return original(request)

    runs._factory = lambda: Governance("https://ss.example.com", "k", transport=httpx.MockTransport(stopped), sleep=lambda s: None)
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.body["kind"] == "halted" and reply.status == 503 and len(web) == 1  # the page was not fetched again
    assert fake.report["outcome"] == "failure"  # the stopped run was finished and reported


def test_a_stopped_run_is_reported_as_a_failure_with_the_reason(tmp_path):
    runs, fake, clock, web, built = make_runs(tmp_path)
    runs.call("fetch_web_page", FETCH)
    fake.heartbeats = [{"continue": False, "reason": "the emergency stop is on; nothing is allowed until an administrator lifts it"}]
    built[0].beat()
    assert runs.close_idle() is True
    assert fake.report["outcome"] == "failure" and "emergency stop" in fake.report["summary"]


def test_a_refused_start_during_the_stop_is_halted(tmp_path):
    runs, fake, _, web, _ = make_runs(tmp_path)

    def stopped(request):
        return httpx.Response(403, json={"detail": "denied: the emergency stop is on; nothing is allowed until an administrator lifts it"})

    runs._factory = lambda: Governance("https://ss.example.com", "k", transport=httpx.MockTransport(stopped), sleep=lambda s: None)
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.body["kind"] == "halted" and reply.status == 503 and web == []


# --- runs and reports --------------------------------------------------------------------------------------

def test_calls_share_one_run_that_is_finished_after_a_quiet_spell_and_reports_the_build(tmp_path):
    runs, fake, clock, web, built = make_runs(tmp_path)
    runs.call("fetch_web_page", FETCH)
    clock.now += 30
    runs.call("fetch_web_page", FETCH)
    starts = [c for c in fake.calls if c[1] == "/runs/start"]
    assert len(starts) == 1 and starts[0][2]["declared"]["model"] == "gpt-test"
    assert runs.close_idle() is False  # still within the quiet window
    clock.now += 500
    assert runs.close_idle() is True
    report = fake.report
    assert report["outcome"] == "success" and report["tool_calls"] == 2 and report["tools"] == ["fetch_web_page"] * 2
    assert report["declared"]["version"] == "1.2" and report["cost_dollars"] == 0.0 and "model runs on the platform" in report["summary"]
    assert "example.com" not in json.dumps(report)  # names only, never arguments
    clock.now += 1
    runs.call("fetch_web_page", FETCH)
    assert len([c for c in fake.calls if c[1] == "/runs/start"]) == 2  # a later call opens a new run


def test_a_run_longer_than_the_time_limit_is_ended_and_a_new_one_opened(tmp_path):
    runs, fake, clock, _, _ = make_runs(tmp_path, idle_seconds=10_000.0)
    runs.call("fetch_web_page", FETCH)
    clock.now += 101  # limits.max_seconds is 100
    runs.call("fetch_web_page", FETCH)
    assert len([c for c in fake.calls if c[1] == "/runs/start"]) == 2


def test_the_tool_call_limit_of_a_run_is_enforced_without_asking_second_shift(tmp_path):
    runs, fake, _, web, _ = make_runs(tmp_path)  # max_tool_calls is 3
    for _ in range(3):
        assert runs.call("fetch_web_page", FETCH).status == 200
    reply = runs.call("fetch_web_page", FETCH)
    assert reply.status == 429 and reply.body["kind"] == "limit" and len(web) == 3 and len(fake.screened) == 3


def test_a_skill_that_fails_is_a_result_not_a_crash_and_an_unknown_skill_is_404(tmp_path):
    runs, _, _, _, _ = make_runs(tmp_path)
    reply = runs.call("fetch_web_page", {"url": "ftp://x"})
    assert reply.status == 200 and reply.body["status"] == "error"
    assert runs.call("nope", {}).status == 404 and runs.call("web_search", {"query": "x"}).status == 404  # not in this definition


def test_a_file_comes_back_inside_the_answer_and_nothing_stays_on_disk(tmp_path):
    runs, _, _, _, _ = make_runs(tmp_path)
    reply = runs.call("create_word_document", {"title": "T", "blocks": [{"type": "paragraph", "text": "Hello"}]})
    assert reply.status == 200 and reply.body["files"][0]["name"].endswith(".docx")
    assert base64.b64decode(reply.body["files"][0]["content_base64"])[:2] == b"PK"
    assert list((tmp_path / "out").iterdir()) == []


# --- the HTTP service and its inbound key ------------------------------------------------------------------

@pytest.fixture
def served(tmp_path):
    started = []

    def start(**kw):
        runs, fake, clock, web, built = make_runs(tmp_path, **kw)
        server = make_skills_server(runs, "127.0.0.1", 0, KEY, server_url="https://skills.example.net")
        threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True).start()
        started.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}", runs, fake, web

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def test_the_inbound_key_is_checked_before_anything_else(served):
    url, _, fake, web = served()
    for headers in ({}, {API_KEY_HEADER: "wrong"}, {"Authorization": f"Bearer {KEY}"}):
        r = httpx.post(url + "/skills/fetch_web_page", json=FETCH, headers=headers)
        assert r.status_code == 401 and KEY not in r.text
    r = httpx.post(url + "/skills/nope", json={}, headers={API_KEY_HEADER: "wrong"})
    assert r.status_code == 401  # a stranger cannot learn which skills exist
    assert fake.calls == [] and web == []


def test_a_call_with_the_key_runs_and_ping_needs_no_key(served):
    url, _, fake, web = served()
    assert httpx.get(url + "/ping").json() == {"status": "Healthy"}
    r = httpx.post(url + "/skills/fetch_web_page", json=FETCH, headers={API_KEY_HEADER: KEY})
    assert r.status_code == 200 and r.json()["status"] == "ok" and len(web) == 1 and fake.screened


def test_a_refusal_is_an_http_error_with_the_kind_in_the_body(served):
    url, _, fake, web = served()
    fake.screens = lambda tool, body: {"allowed": False, "kind": "halted", "reason": "the emergency stop is on"}
    r = httpx.post(url + "/skills/fetch_web_page", json=FETCH, headers={API_KEY_HEADER: KEY})
    assert r.status_code == 503 and r.json()["kind"] == "halted" and web == []


def test_bad_bodies_are_refused_before_any_governance_call(served):
    url, _, fake, _ = served()
    h = {API_KEY_HEADER: KEY}
    assert httpx.post(url + "/skills/fetch_web_page", content=b"[1]", headers={**h, "content-type": "application/json"}).status_code == 400
    assert httpx.post(url + "/skills/fetch_web_page", content=b"{" * 3, headers=h).status_code == 400
    assert httpx.post(url + "/skills/a/b", json={}, headers=h).status_code == 404
    assert fake.calls == []


def test_the_openapi_file_is_served_to_the_key_holder_only(served):
    url, _, _, _ = served()
    assert httpx.get(url + "/openapi.json").status_code == 401
    spec = httpx.get(url + "/openapi.json", headers={API_KEY_HEADER: KEY}).json()
    assert check_foundry_openapi(spec) == [] and KEY not in json.dumps(spec)
