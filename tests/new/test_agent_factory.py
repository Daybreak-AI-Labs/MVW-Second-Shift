"""The agent factory: draft with a model, edit, test, submit, approve, release.

Hermetic. No model is called: a scripted model replaces the client the factory makes, and the runtime's own loop runs
every test against it. Each person is a forwarded identity from a trusted proxy (loopback is trusted in these tests);
a person's role comes from the role list, as an administrator would assign it. Skips cleanly when the runtime is not
installed (it is an optional extra).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("second_shift_runtime", reason="the agent factory needs the second-shift-runtime package")

from second_shift_runtime.models import ModelClient, ModelError, ModelReply, ToolCall  # noqa: E402

MODEL_KEY = "factory-model-key-9f3a"  # pragma: allowlist secret
MODEL_ENDPOINT = "https://factory-model.example.test/openai/v1"
PEOPLE = {"alice": "operator", "bob": "operator", "carol": "approver", "dave": "viewer", "erin": "approver", "boss": "admin"}

PROPOSAL = {
    "name": "Policy helper",
    "description": "Answers staff questions about the travel policy.",
    "instructions": "You answer staff questions about travel. Never give legal advice. Say so when you do not know.",
    "skills": [{"name": "create_word_document"}],
    "limits": {"max_steps": 6, "max_tool_calls": 4},
}


class FakeModel(ModelClient):
    """Plays back replies in order (the last one repeats); an item may be an exception to raise."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def complete(self, system, messages, tools, *, timeout=None):
        self.calls.append({"system": system, "messages": list(messages), "tools": [t.name for t in tools]})
        item = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(item, Exception):
            raise item
        return item


def text(answer, usage=(100, 20)):
    return ModelReply(answer, [], usage[0], usage[1])


def tool(name, args, usage=(100, 20)):
    return ModelReply("", [ToolCall("call_1", name, args)], usage[0], usage[1])


def proposal_reply(**over):
    return text(json.dumps({**PROPOSAL, **over}))


def _write_private(path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch, request):
    """One installation with its own files, sign-in by forwarded identity, and the factory pointed at a fake model."""
    from maverick import config, governed_records, world_model
    from maverick.audit import signing
    from maverick_dashboard import rbac

    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(f"factory:{request.node.nodeid}".encode()).hexdigest())
    signing._reset_injected_keypair_cache()
    governed_records._reset_process_authority_pin_for_testing()

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    key = b"k" * 32
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.setenv("FACTORY_TEST_ENDPOINT", MODEL_ENDPOINT)
    monkeypatch.setenv("FACTORY_TEST_KEY", MODEL_KEY)
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_TENANT",
                 "MAVERICK_TENANT_BY_USER", "MAVERICK_MFA_REQUIRE", "MAVERICK_SEPARATE_APPROVER", "MAVERICK_PG_DSN",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_OIDC_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_PROXY_AUTH", "1")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    write_config(tmp_path)
    _write_private(rbac.store_path(), json.dumps({f"user:{p}": r for p, r in PEOPLE.items()}))
    config.reset_config_cache()

    from maverick.factory import testing

    monkeypatch.setattr(testing, "RUN_INLINE", True)
    yield tmp_path
    signing._reset_injected_keypair_cache()
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def write_config(tmp_path, **factory):
    from maverick import config

    values = {"provider": "foundry_openai", "endpoint_env": "FACTORY_TEST_ENDPOINT", "api_key_env": "FACTORY_TEST_KEY",
              "deployment": "gpt-test", "input_price_per_million": 2.0, "output_price_per_million": 8.0,
              "max_test_cases": 3, "max_case_seconds": 60, "max_test_run_seconds": 300, "max_test_run_cost_dollars": 1.0}
    values.update(factory)
    lines = ["[factory]"] + [f'{k} = "{v}"' if isinstance(v, str) else f"{k} = {v}" for k, v in values.items() if v is not None]
    lines += ["", "[auth.proxy]", "enabled = true", "trust_loopback = true"]
    (tmp_path / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture
def model(monkeypatch):
    """The scripted model every factory call gets. Set ``model.script`` (a list of replies) per test."""
    from maverick.factory import models

    holder = type("Holder", (), {})()
    holder.client = FakeModel([text("The policy allows economy class.")])
    holder.built = []

    def build(settings):
        holder.built.append(settings)
        return holder.client

    monkeypatch.setattr(models, "build_client", build)
    return holder


@pytest.fixture
def app():
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def person(app):
    def client(name):
        return TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000),
                          headers={"Origin": "http://127.0.0.1", "X-Forwarded-User": name})
    return client


@pytest.fixture
def world(app):
    from maverick_dashboard._shared import _world

    return _world()


def new_agent(client, **over):
    parts = {**PROPOSAL, **over}
    made = client.post("/api/v1/factory/agents", json={"brief": {"purpose": "Answer travel questions"}, "parts": parts})
    assert made.status_code == 201, made.text
    return made.json()


CASE = {"name": "Mentions economy", "input": "What class may I fly?",
        "checks": [{"kind": "answer_contains", "value": "economy"}]}


def add_case(client, agent, **over):
    out = client.post(f"/api/v1/factory/agents/{agent['id']}/cases", json={**CASE, **over})
    assert out.status_code == 201, out.text
    return out.json()


def run_tests(client, agent):
    n = agent["tip"]
    out = client.post(f"/api/v1/factory/agents/{agent['id']}/versions/{n}/tests")
    assert out.status_code == 202, out.text
    return client.get(f"/api/v1/factory/agents/{agent['id']}").json()


def agent_with_passing_tests(client, model, **over):
    agent = new_agent(client, **over)
    add_case(client, agent)
    return run_tests(client, agent)


def tip(agent):
    return agent["versions"][-1]


def submit(client, agent):
    return client.post(f"/api/v1/factory/agents/{agent['id']}/versions/{agent['tip']}/submit")


def approve(client, world, approval_id):
    from maverick.approval_cards import decode_approval_detail

    card = decode_approval_detail(world.get_approval(approval_id).detail)
    return client.post(f"/api/v1/approvals/{approval_id}/approve", json={"acknowledged": True},
                       headers={"X-Second-Shift-Approval-Binding": card["binding_sha256"]})


# --------------------------------------------------------------------------------------------------- drafting

def test_a_valid_proposal_is_checked_and_shown_but_not_saved(person, model):
    model.client = FakeModel([proposal_reply()])
    out = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "Answer travel questions", "must_not": "Never give legal advice"}})
    assert out.status_code == 200, out.text
    body = out.json()
    assert body["ok"] is True and body["parts"]["name"] == "Policy helper" and body["parts"]["skills"] == [{"name": "create_word_document"}]
    assert body["usage"]["cost"] == pytest.approx((100 * 2.0 + 20 * 8.0) / 1e6)
    prompt = model.client.calls[0]
    assert "create_word_document" in prompt["system"] and "Never give legal advice" in prompt["messages"][0].text
    assert person("alice").get("/api/v1/factory/agents").json() == {"agents": []}, "a proposal is never saved by drafting"


@pytest.mark.parametrize("bad, reason", [
    ({"skills": [{"name": "launch_missiles"}]}, "launch_missiles"),
    ({"instructions": ""}, "instructions"),
    ({"limits": {"max_steps": 9999}}, "max_steps"),
    ({"limits": ["many"]}, "limits"),
    ({"skills": [{"name": "create_word_document", "settings": {"colour": "red"}}]}, "colour"),
])
def test_a_proposal_that_fails_validation_is_shown_with_the_reasons_and_never_saved(person, model, bad, reason):
    model.client = FakeModel([proposal_reply(**bad)])
    body = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "Answer travel questions"}}).json()
    assert body["ok"] is False and body["reasons"] and reason in " ".join(body["reasons"])
    assert body["excerpt"].startswith("{")
    assert person("alice").get("/api/v1/factory/agents").json() == {"agents": []}


@pytest.mark.parametrize("junk", ["I am sorry, I cannot do that.", "{not json", "[1, 2, 3]", ""])
def test_a_model_that_returns_junk_gives_a_plain_reason(person, model, junk):
    model.client = FakeModel([text(junk)])
    body = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "x"}}).json()
    assert body["ok"] is False and "not a definition" in body["reasons"][0]
    assert person("alice").get("/api/v1/factory/agents").json() == {"agents": []}


def test_a_fenced_answer_and_extra_fields_are_handled_and_the_model_cannot_choose_the_model(person, model):
    sent = {**PROPOSAL, "model": {"provider": "foundry_openai", "deployment": "evil"}, "id": "other"}
    model.client = FakeModel([text("Here you go:\n```json\n" + json.dumps(sent) + "\n```")])
    body = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "x"}}).json()
    assert body["ok"] is True and "model" in body["notes"][0] and "model" not in body["parts"]
    saved = person("alice").post("/api/v1/factory/agents", json={"brief": {"purpose": "x"}, "parts": body["parts"]}).json()
    assert tip(saved)["definition"]["model"]["deployment"] == "gpt-test" and saved["agent_id"] == "policy-helper"


def test_a_model_error_is_said_plainly(person, model):
    model.client = FakeModel([ModelError("The model service refused the key (status 401). Check the key and the deployment name.")])
    out = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "x"}})
    assert out.status_code == 502 and "refused the key" in out.json()["detail"]
    assert MODEL_KEY not in out.text


def test_drafting_needs_the_model_to_be_set_up(person, model, installation, monkeypatch):
    monkeypatch.delenv("FACTORY_TEST_KEY")
    out = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "x"}})
    assert out.status_code == 409 and "FACTORY_TEST_KEY" in out.json()["detail"] and not model.built
    page = person("alice").get("/factory/new")
    assert page.status_code == 200 and "model is not set up" in page.text and "FACTORY_TEST_KEY" in page.text


def test_the_brief_needs_a_purpose(person, model):
    out = person("alice").post("/api/v1/factory/draft", json={"brief": {"purpose": "  "}})
    assert out.status_code == 422 and "what the agent is for" in out.json()["detail"]


# ----------------------------------------------------------------------------------------------- editing

def test_a_new_agent_starts_as_draft_one_with_a_fingerprint_and_the_servers_own_model_section(person, model):
    agent = new_agent(person("alice"))
    v = tip(agent)
    assert (v["number"], v["state"], v["revision"], v["made_by"]) == (1, "draft", 1, "user:alice")
    d = v["definition"]
    assert d["id"] == "policy-helper" and d["version"] == "1"
    assert d["model"] == {"provider": "foundry_openai", "endpoint_env": "FACTORY_TEST_ENDPOINT", "api_key_env": "FACTORY_TEST_KEY",
                          "deployment": "gpt-test", "max_output_tokens": 2000, "input_price_per_million": 2.0, "output_price_per_million": 8.0}
    assert d["governance"] == {"address_env": "SECOND_SHIFT_URL", "agent_key_env": "SECOND_SHIFT_AGENT_KEY"}
    assert d["limits"]["max_cost_dollars"] == 1.0 and d["limits"]["max_steps"] == 6
    from second_shift_runtime.definition import parse_definition

    assert v["config_digest"] == parse_definition(d).config_digest and len(v["config_digest"]) == 64
    assert MODEL_KEY not in json.dumps(agent)


def test_two_agents_with_one_name_get_different_identities(person, model):
    assert new_agent(person("alice"))["agent_id"] == "policy-helper"
    assert new_agent(person("alice"))["agent_id"] == "policy-helper-2"


def test_saving_an_edit_makes_a_new_revision_and_a_change_after_testing_makes_it_untested_again(person, model):
    alice = person("alice")
    agent = agent_with_passing_tests(alice, model)
    assert tip(agent)["state"] == "tested" and tip(agent)["revision"] == 1
    edited = alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={
        "parts": {"instructions": "You answer travel questions. Be brief."}, "base_version": 1, "base_revision": 1})
    assert edited.status_code == 200, edited.text
    v = tip(edited.json())
    assert (v["number"], v["state"], v["revision"]) == (1, "draft", 2)
    assert v["definition"]["instructions"].endswith("Be brief.") and v["config_digest"] != tip(agent)["config_digest"]
    assert v["tests"]["stale"] is True and v["gate"]["open"] is False and "changed after its last test run" in v["gate"]["reason"]
    assert v["last_changed_by"] == "user:alice"


def test_saving_the_same_thing_again_makes_no_new_revision(person, model):
    alice = person("alice")
    agent = new_agent(alice)
    same = alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={"parts": {"name": "Policy helper"}, "base_version": 1, "base_revision": 1})
    assert same.status_code == 200 and tip(same.json())["revision"] == 1


def test_an_edit_that_fails_validation_saves_nothing_and_says_why(person, model):
    alice = person("alice")
    agent = new_agent(alice)
    out = alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={
        "parts": {"skills": [{"name": "create_word_document", "risk": "banana"}]}, "base_version": 1, "base_revision": 1})
    assert out.status_code == 422 and "risk" in out.json()["detail"]
    assert tip(alice.get(f"/api/v1/factory/agents/{agent['id']}").json())["revision"] == 1
    lowered = alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={
        "parts": {"skills": [{"name": "fetch_web_page", "risk": "low"}, {"name": "create_word_document", "risk": "low"}]}, "base_version": 1, "base_revision": 1})
    assert lowered.status_code == 200
    out = alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={"parts": {"model": {"deployment": "x"}}, "base_version": 1, "base_revision": 2})
    assert out.status_code == 422


def test_an_edit_made_from_a_stale_page_is_refused(person, model):
    alice, bob = person("alice"), person("bob")
    agent = new_agent(alice)
    url = f"/api/v1/factory/agents/{agent['id']}/definition"
    assert alice.put(url, json={"parts": {"description": "One"}, "base_version": 1, "base_revision": 1}).status_code == 200
    stale = bob.put(url, json={"parts": {"description": "Two"}, "base_version": 1, "base_revision": 1})
    assert stale.status_code == 409 and "Someone else changed" in stale.json()["detail"]


def test_editing_a_released_agent_starts_the_next_version(person, model, world):
    agent = released_agent(person, model, world)
    out = person("alice").put(f"/api/v1/factory/agents/{agent['id']}/definition", json={
        "parts": {"description": "Now with more"}, "base_version": 1, "base_revision": tip(agent)["revision"]}).json()
    assert [(v["number"], v["state"]) for v in out["versions"]] == [(1, "released"), (2, "draft")]
    assert tip(out)["definition"]["version"] == "2" and out["versions"][0]["definition"]["description"] != "Now with more"
    assert out["state"] == "draft" and out["released"] == 1


# ----------------------------------------------------------------------------------------- test cases & checks

def test_cases_are_bounded_and_every_case_needs_a_check(person, model):
    alice = person("alice")
    agent = new_agent(alice)
    for _ in range(3):
        add_case(alice, agent)
    over = alice.post(f"/api/v1/factory/agents/{agent['id']}/cases", json=CASE)
    assert over.status_code == 409 and "at most 3" in over.json()["detail"]
    bare = alice.post(f"/api/v1/factory/agents/{agent['id']}/cases", json={"name": "x", "input": "hi", "checks": []})
    assert bare.status_code == 422
    bad = alice.post(f"/api/v1/factory/agents/{agent['id']}/cases", json={"name": "x", "input": "hi", "checks": [{"kind": "feels_right", "value": "1"}]})
    assert bad.status_code == 422 and "must be one of" in bad.json()["detail"]
    kinds = alice.post(f"/api/v1/factory/agents/{agent['id']}/cases", json={"name": "x", "input": "hi", "checks": [{"kind": "makes_file", "value": "pdf"}]})
    assert kinds.status_code in (409, 422)


def test_every_kind_of_check_passes_and_fails_correctly():
    from maverick.factory.testing import Outcome, evaluate_checks

    outcome = Outcome(True, "Your fare is Economy class.", ["fetch_web_page", "fetch_web_page"], [{"name": "plan-1.docx", "size": 10, "sha256": "x"}], 0.002)

    def one(kind, value):
        (result,) = evaluate_checks([{"kind": kind, "value": value}], outcome)
        return result["passed"]

    assert one("uses_skill", "fetch_web_page") and not one("uses_skill", "web_search")
    assert one("not_uses_skill", "web_search") and not one("not_uses_skill", "fetch_web_page")
    assert one("answer_contains", "economy CLASS") and not one("answer_contains", "business")
    assert one("answer_not_contains", "business") and not one("answer_not_contains", "economy")
    assert one("makes_file", "docx") and not one("makes_file", "xlsx")
    assert one("max_cost", 0.01) and not one("max_cost", 0.001)
    unpriced = Outcome(True, "x", [], [], None)
    (result,) = evaluate_checks([{"kind": "max_cost", "value": 1.0}], unpriced)
    assert result["passed"] is False and "prices" in result["detail"]


def test_a_run_goes_through_the_runtime_with_the_stand_in_and_records_everything(person, model, world):
    alice = person("alice")
    agent = new_agent(alice, skills=[{"name": "create_word_document"}, {"name": "fetch_web_page", "risk": "medium"}])
    add_case(alice, agent, name="Makes a memo", input="Write the memo",
             checks=[{"kind": "uses_skill", "value": "create_word_document"}, {"kind": "makes_file", "value": "docx"},
                     {"kind": "not_uses_skill", "value": "fetch_web_page"}, {"kind": "answer_contains", "value": "memo is ready"},
                     {"kind": "max_cost", "value": 0.5}])
    model.client = FakeModel([tool("create_word_document", {"title": "Memo", "blocks": [{"type": "paragraph", "text": "Hello"}]}, (300, 40)),
                              text("The memo is ready.", (400, 30))])
    out = run_tests(alice, agent)
    t = tip(out)
    assert t["state"] == "tested" and t["tests"]["status"] == "finished" and t["tests"]["passed"] is True and t["gate"]["open"] is True
    (result,) = t["tests"]["results"]
    assert result["status"] == "passed" and all(c["passed"] for c in result["checks"])
    assert result["tools"] == ["create_word_document"] and result["files"][0]["name"].endswith(".docx")
    assert result["screens"] == [{"tool": "create_word_document", "risk": "low", "detail": result["screens"][0]["detail"], "allowed": True}]
    assert result["cost"] == pytest.approx((700 * 2.0 + 70 * 8.0) / 1e6) and result["seconds"] >= 0
    assert any("create_word_document" in s for s in result["steps"]) and result["answer"] == "The memo is ready."
    assert t["tests"]["total_cost"] == pytest.approx(result["cost"])
    assert world.pending_approvals() == [] and external_roster() == [], "a test creates no outside agent and no approval"


def test_a_failed_check_fails_the_case_and_keeps_the_gate_shut(person, model):
    alice = person("alice")
    agent = new_agent(alice)
    add_case(alice, agent, checks=[{"kind": "answer_contains", "value": "business class"}])
    out = run_tests(alice, agent)
    t = tip(out)
    assert t["state"] == "draft" and t["tests"]["passed"] is False
    assert t["tests"]["results"][0]["status"] == "failed" and "not in the answer" in t["tests"]["results"][0]["checks"][0]["detail"]
    assert t["gate"]["open"] is False and "did not pass" in t["gate"]["reason"]


def test_a_run_that_cannot_finish_is_an_error_not_a_pass(person, model):
    alice = person("alice")
    agent = new_agent(alice)
    add_case(alice, agent, checks=[{"kind": "answer_not_contains", "value": "zzz"}])
    model.client = FakeModel([ModelError("The model took too long to answer.")])
    out = run_tests(alice, agent)
    result = tip(out)["tests"]["results"][0]
    assert result["status"] == "error" and "took too long" in result["reason"] and tip(out)["tests"]["passed"] is False


def test_a_tool_the_definition_does_not_rate_that_way_is_refused_by_the_stand_in():
    from maverick.factory.testing import StandInGovernance

    gov = StandInGovernance({"fetch_web_page": "medium"})
    assert gov.screen("fetch_web_page", "medium", "Fetch a page.").allowed is True
    assert gov.screen("fetch_web_page", "low", "Fetch a page.").allowed is False
    assert gov.screen("web_search", "low", "Search.").allowed is False
    assert [s["allowed"] for s in gov.screens] == [True, False, False]


def test_the_number_of_cases_run_time_and_cost_bounds_a_test_run(person, model, installation):
    alice = person("alice")
    agent = new_agent(alice)
    add_case(alice, agent)
    # Over the cost bound: refused before anything runs, and no model call is made.
    write_config(installation, max_test_run_cost_dollars=0.000001)
    refused = alice.post(f"/api/v1/factory/agents/{agent['id']}/versions/1/tests")
    assert refused.status_code == 409 and "estimated to cost" in refused.json()["detail"] and not model.client.calls
    # No prices: a cost bound cannot be checked, so the run is refused rather than unbounded.
    write_config(installation, input_price_per_million=None, output_price_per_million=None)
    no_prices = person("alice").post(f"/api/v1/factory/agents/{agent['id']}/versions/1/tests")
    assert no_prices.status_code == 409 and "prices" in no_prices.json()["detail"] and not model.client.calls
    # Fewer cases allowed than the agent has: refused.
    write_config(installation, max_test_cases=1)
    add = alice.post(f"/api/v1/factory/agents/{agent['id']}/cases", json=CASE)
    assert add.status_code == 409
    write_config(installation, max_test_cases=3)
    ok = alice.post(f"/api/v1/factory/agents/{agent['id']}/versions/1/tests")
    assert ok.status_code == 202, ok.text


def test_the_whole_run_stops_when_its_cost_is_used_up(person, model, installation):
    alice = person("alice")
    agent = new_agent(alice, limits={"max_steps": 2, "max_cost_dollars": 0.5})
    for n in range(3):
        add_case(alice, agent, name=f"Case {n + 1}")
    write_config(installation, max_test_run_cost_dollars=2.0, input_price_per_million=1000.0, output_price_per_million=1000.0)
    model.client = FakeModel([text("economy", (1000, 600))])  # $1.60 a call at these prices
    out = run_tests(alice, agent)
    results = tip(out)["tests"]["results"]
    assert len(results) == 3 and [r["status"] for r in results] == ["error", "error", "error"]
    assert "passed the limit" in results[0]["reason"] and "cost limit" in results[2]["reason"] and results[2]["cost"] == 0.0
    assert len(model.client.calls) == 2, "the third case was never started"
    assert tip(out)["tests"]["passed"] is False and tip(out)["tests"]["total_cost"] == pytest.approx(3.2)


def test_a_changed_case_list_invalidates_the_tests(person, model):
    alice = person("alice")
    agent = agent_with_passing_tests(alice, model)
    assert tip(agent)["state"] == "tested"
    out = add_case(alice, agent, name="Another")
    assert tip(out)["state"] == "draft" and tip(out)["gate"]["open"] is False and "test cases changed" in tip(out)["gate"]["reason"]


def test_tests_cut_off_by_a_restart_are_ended_plainly(person, model):
    from maverick.factory import store

    alice = person("alice")
    agent = new_agent(alice)
    add_case(alice, agent)

    def stuck(rec):
        rec["versions"][-1]["tests"] = {"run_id": "gone", "status": "running", "config_digest": "x", "cases_digest": "y", "results": [], "case_count": 1,
                                        "started_at": 1.0, "started_by": "user:alice", "total_cost": 0.0, "estimated_cost": None, "note": ""}

    store.change(agent["id"], "user:alice", "test", stuck)
    seen = alice.get(f"/api/v1/factory/agents/{agent['id']}").json()
    assert tip(seen)["tests"]["status"] == "finished" and "restarted" in tip(seen)["tests"]["note"]
    assert run_tests(alice, agent)["versions"][-1]["state"] == "tested"


# ------------------------------------------------------------------------------------------------- release

def external_roster():
    from maverick import external_agents

    return external_agents.roster()


def released_agent(person, model, world, *, approver="carol", **over):
    agent = agent_with_passing_tests(person("alice"), model, **over)
    submitted = submit(person("alice"), agent)
    assert submitted.status_code == 202, submitted.text
    approval_id = tip(submitted.json())["approval"]["id"]
    assert approve(person(approver), world, approval_id).status_code == 204
    return person("alice").get(f"/api/v1/factory/agents/{agent['id']}").json()


def test_a_version_cannot_be_submitted_until_every_case_passed_on_that_exact_version(person, model, world):
    alice = person("alice")
    agent = new_agent(alice)
    assert submit(alice, agent).status_code == 409 and "tested" in submit(alice, agent).json()["detail"]
    add_case(alice, agent)
    assert submit(alice, agent).status_code == 409
    agent = run_tests(alice, agent)
    alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={"parts": {"description": "changed"}, "base_version": 1, "base_revision": 1})
    again = submit(alice, agent)
    assert again.status_code == 409 and "Only a tested version" in again.json()["detail"]
    assert world.pending_approvals() == []
    model.client = FakeModel([text("business class only")])
    failed = run_tests(alice, alice.get(f"/api/v1/factory/agents/{agent['id']}").json())
    assert tip(failed)["tests"]["passed"] is False and submit(alice, failed).status_code == 409
    assert world.pending_approvals() == []


def test_submitting_creates_an_approval_that_shows_on_the_approvals_page(person, model, world):
    alice = person("alice")
    agent = agent_with_passing_tests(alice, model)
    out = submit(alice, agent)
    assert out.status_code == 202, out.text
    v = tip(out.json())
    assert v["state"] == "waiting_for_approval" and v["approval"]["id"] and v["approval"]["submitted_by"] == "user:alice"
    (pending,) = world.pending_approvals()
    assert pending.provenance == "factory_release" and pending.requested_by == "user:alice" and pending.id == v["approval"]["id"]
    assert pending.action == f"factory_release:{agent['id']}:1"
    page = person("carol").get("/approvals")
    assert page.status_code == 200 and f'id="approval-{pending.id}"' in page.text and "Agent ready to release" in page.text
    assert "Policy helper" in page.text and "Skills and their risk" in page.text
    listed = person("carol").get("/api/v1/approvals").json()["approvals"]
    assert [a["id"] for a in listed] == [pending.id]
    # Nothing is enrolled yet, and the version cannot change while it waits.
    assert external_roster() == []
    edit = alice.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={"parts": {"description": "x"}, "base_version": 1, "base_revision": 1})
    assert edit.status_code == 409 and "waiting for approval" in edit.json()["detail"]
    assert alice.post(f"/api/v1/factory/agents/{agent['id']}/cases", json=CASE).status_code == 409
    assert submit(alice, out.json()).status_code == 409


def test_the_person_who_last_changed_or_submitted_it_cannot_approve_it(person, model, world):
    # alice made and tested it; bob saved the last change and submitted it; alice may not approve (she did not change last, but
    # the rule is about who changed it LAST and who submitted), bob may not; erin, who did neither, may.
    alice, bob = person("alice"), person("bob")
    agent = agent_with_passing_tests(alice, model)
    bob.put(f"/api/v1/factory/agents/{agent['id']}/definition", json={"parts": {"description": "Bob's change"}, "base_version": 1, "base_revision": 1})
    agent = run_tests(bob, alice.get(f"/api/v1/factory/agents/{agent['id']}").json())
    assert tip(agent)["last_changed_by"] == "user:bob"
    submitted = submit(alice, agent)
    approval_id = tip(submitted.json())["approval"]["id"]
    for name in ("alice", "bob"):  # alice submitted it; bob changed it last. Both hold the operate role, which implies approve.
        denied = approve(person(name), world, approval_id)
        assert denied.status_code == 403, (name, denied.text)
        assert "someone else must approve" in denied.json()["detail"]
    assert world.get_approval(approval_id).status == "pending"
    page = person("alice").get("/approvals").text
    assert "someone else must approve" in page or "disabled" in page
    assert approve(person("erin"), world, approval_id).status_code == 204
    done = alice.get(f"/api/v1/factory/agents/{agent['id']}").json()
    assert tip(done)["state"] == "released" and tip(done)["approval"]["approved_by"] == ["user:erin"]


def test_approving_enrolls_the_agent_with_its_skills_ratings_and_limits_and_releases_the_version(person, model, world):
    from maverick import agent_trust, external_agents

    agent = released_agent(person, model, world, skills=[{"name": "create_word_document"}, {"name": "fetch_web_page", "risk": "medium"}],
                           limits={"max_steps": 6, "max_tool_calls": 4, "max_seconds": 120})
    v = tip(agent)
    assert v["state"] == "released" and v["released_at"] and agent["state"] == "released" and agent["released"] == 1
    assert agent["enrollment"]["external_agent_id"] == "policy-helper" and agent["enrollment"]["platform"] == "custom"
    assert agent["enrollment"]["config_digest"] == v["config_digest"] and agent["enrollment"]["enrolled_version"] == 1
    (row,) = [r for r in external_agents.roster() if r["id"] == "policy-helper"]
    assert row["platform"] == "custom" and row["max_risk"] == "medium" and row["owner"] == "user:alice"
    entry = agent_trust.lookup("policy-helper")
    assert sorted(entry.allow_tools) == ["create_word_document", "fetch_web_page"] and entry.max_wall_seconds == 120
    sidecar = external_agents._load_sidecar()["policy-helper"]
    assert sidecar["tool_risks"] == {"create_word_document": "low", "fetch_web_page": "medium"}
    assert "user:carol" in sidecar["enrolled_by"]
    assert external_agents.screen("policy-helper", "create_word_document", risk="low")["allowed"] is True
    assert external_agents.screen("policy-helper", "web_search", risk="low")["allowed"] is False
    # A released version never changes; the page says where to find the agent.
    page = person("alice").get(f"/factory/{agent['id']}")
    assert page.status_code == 200 and "policy-helper" in page.text
    assert world.pending_approvals() == []


def test_no_access_key_is_made_by_a_release(person, model, world):
    from maverick import external_agents

    released_agent(person, model, world)
    (row,) = [r for r in external_agents.roster() if r["id"] == "policy-helper"]
    assert not row["credentials"]


def test_a_denied_release_sends_the_version_back_and_it_can_be_submitted_again(person, model, world):
    alice = person("alice")
    agent = agent_with_passing_tests(alice, model)
    approval_id = tip(submit(alice, agent).json())["approval"]["id"]
    denied = person("carol").post(f"/api/v1/approvals/{approval_id}/deny", json={"reason": "Needs a legal review"})
    assert denied.status_code == 204
    back = alice.get(f"/api/v1/factory/agents/{agent['id']}").json()
    assert tip(back)["state"] == "tested" and tip(back)["approval"]["outcome"] == "denied" and external_roster() == []
    again = submit(alice, back)
    assert again.status_code == 202 and tip(again.json())["approval"]["id"] != approval_id


def test_a_release_is_never_made_on_an_approval_the_rules_would_have_refused(person, model, world):
    # A decision that reached the queue without the vote rules (a bug elsewhere, say) still releases nothing: the release
    # checks who approved before it enrolls anything, and sends the version back.
    from maverick import channel_approvals
    from maverick.factory import store

    alice = person("alice")
    agent = agent_with_passing_tests(alice, model)
    approval_id = tip(submit(alice, agent).json())["approval"]["id"]
    event = world.decide_approval_audited(approval_id, "approved", decided_by="user:alice")
    assert channel_approvals.audit_approval_decision(world, event) is True
    assert world.get_approval(approval_id).status == "approved"
    version = store.latest(store.get(agent["id"]))
    assert version["state"] == "tested" and version["approval"]["outcome"] == "refused" and external_roster() == []


def test_a_second_version_updates_the_enrollment_and_becomes_the_approved_configuration(person, model, world, monkeypatch):
    from maverick import agent_drift, agent_trust

    calls = []
    real = agent_drift.approve_declared_configuration
    monkeypatch.setattr(agent_drift, "approve_declared_configuration", lambda *a, **k: calls.append(k) or real(*a, **k))
    first = released_agent(person, model, world, skills=[{"name": "create_word_document"}, {"name": "fetch_web_page"}])
    assert sorted(agent_trust.lookup("policy-helper").allow_tools) == ["create_word_document", "fetch_web_page"]
    alice = person("alice")
    edited = alice.put(f"/api/v1/factory/agents/{first['id']}/definition", json={
        "parts": {"skills": [{"name": "create_word_document"}], "limits": {"max_seconds": 90}}, "base_version": 1, "base_revision": 1}).json()
    assert tip(edited)["number"] == 2
    run_tests(alice, edited)
    again = alice.get(f"/api/v1/factory/agents/{first['id']}").json()
    approval_id = tip(submit(alice, again).json())["approval"]["id"]
    assert approve(person("erin"), world, approval_id).status_code == 204
    out = alice.get(f"/api/v1/factory/agents/{first['id']}").json()
    assert [(v["number"], v["state"]) for v in out["versions"]] == [(1, "retired"), (2, "released")]
    assert out["enrollment"]["enrolled_version"] == 2 and out["enrollment"]["config_digest"] == tip(out)["config_digest"] != first["versions"][0]["config_digest"]
    entry = agent_trust.lookup("policy-helper")
    assert sorted(entry.allow_tools) == ["create_word_document"] and entry.max_wall_seconds == 90
    assert "fetch_web_page" in entry.deny_tools, "a skill taken out of the agent is refused at the gateway, not just forgotten"
    assert len([r for r in external_roster() if r["id"] == "policy-helper"]) == 1
    assert calls[-1]["config_digest"] == tip(out)["config_digest"] and calls[-1]["version"] == "2" and calls[-1]["model"] == "gpt-test"


def test_retiring_needs_admin_and_cuts_the_agent_off(person, model, world):
    agent = released_agent(person, model, world)
    url = f"/api/v1/factory/agents/{agent['id']}/retire"
    assert person("alice").post(url).status_code == 403 and person("carol").post(url).status_code == 403
    out = person("boss").post(url)
    assert out.status_code == 200, out.text
    assert tip(out.json())["state"] == "retired" and out.json()["enrollment"]["status"] == "removed" and external_roster() == []
    assert person("boss").post(url).status_code == 409


# ------------------------------------------------------------------------------------------ who may do what

def test_permissions_for_each_action(app, person, model, world):
    alice = person("alice")
    agent = agent_with_passing_tests(alice, model)
    base = f"/api/v1/factory/agents/{agent['id']}"
    actions = {
        "draft": ("post", "/api/v1/factory/draft", {"brief": {"purpose": "x"}}),
        "create": ("post", "/api/v1/factory/agents", {"brief": {"purpose": "x"}, "parts": PROPOSAL}),
        "edit": ("put", base + "/definition", {"parts": {"description": "z"}, "base_version": 1, "base_revision": 1}),
        "add case": ("post", base + "/cases", CASE),
        "run tests": ("post", base + "/versions/1/tests", None),
        "submit": ("post", base + "/versions/1/submit", None),
    }
    for who in ("dave", "carol"):  # a viewer and an approver can look, never build
        c = person(who)
        assert c.get("/api/v1/factory/agents").status_code == 200 and c.get(base).status_code == 200 and c.get("/factory").status_code == 200
        assert c.get(f"/factory/{agent['id']}").status_code == 200
        for name, (method, url, body) in actions.items():
            out = getattr(c, method)(url, **({"json": body} if body is not None else {}))
            assert out.status_code == 403, (who, name, out.status_code)
        assert c.get("/factory/new").status_code == 403
        assert c.post(base + "/retire").status_code == 403
    assert person("alice").get("/factory/new").status_code == 200
    stranger = TestClient(app, base_url="http://127.0.0.1", client=("10.9.9.9", 5), headers={"X-Forwarded-User": "alice"})
    assert stranger.get("/api/v1/factory/agents").status_code in (401, 403) and stranger.get("/factory").status_code in (401, 403)


def test_approving_a_release_needs_the_approve_permission(person, model, world):
    alice = person("alice")
    approval_id = tip(submit(alice, agent_with_passing_tests(alice, model)).json())["approval"]["id"]
    from maverick.approval_cards import decode_approval_detail

    binding = decode_approval_detail(world.get_approval(approval_id).detail)["binding_sha256"]
    out = person("dave").post(f"/api/v1/approvals/{approval_id}/approve", json={"acknowledged": True}, headers={"X-Second-Shift-Approval-Binding": binding})
    assert out.status_code == 403 and world.get_approval(approval_id).status == "pending"


# ------------------------------------------------------------------------------- storage, secrets and absence

def test_records_survive_a_restart(person, model):
    from maverick import governed_records
    from maverick.factory import store

    agent = agent_with_passing_tests(person("alice"), model)
    governed_records._reset_process_authority_pin_for_testing()
    fresh = governed_records.GovernedRecordStore("factory_agents", "FAC", "factory_agent")
    again = fresh.get(agent["id"])
    assert again is not None and again["versions"][0]["config_digest"] == tip(agent)["config_digest"] and again["cases"][0]["name"] == CASE["name"]
    assert [r["id"] for r in store.list_agents()] == [agent["id"]]


def test_a_model_key_never_appears_in_pages_logs_or_records(person, model, world, caplog, installation):
    caplog.set_level(logging.DEBUG)
    alice = person("alice")
    seen = []
    model.client = FakeModel([proposal_reply()])
    seen.append(alice.post("/api/v1/factory/draft", json={"brief": {"purpose": "x"}}).text)
    model.client = FakeModel([text("The policy allows economy class.")])
    agent = agent_with_passing_tests(alice, model)
    seen.append(json.dumps(agent))
    approval_id = tip(submit(alice, agent).json())["approval"]["id"]
    approve(person("erin"), world, approval_id)
    for path in ("/factory", "/factory/new", f"/factory/{agent['id']}", "/approvals", "/api/v1/factory/status", "/api/v1/factory/agents"):
        seen.append(alice.get(path).text)
    model.client = FakeModel([ModelError("The model service refused the key (status 401). Check the key and the deployment name.")])
    seen.append(alice.post("/api/v1/factory/draft", json={"brief": {"purpose": "x"}}).text)
    stored = "".join(p.read_text(errors="ignore") for p in installation.rglob("*") if p.is_file() and p.suffix in (".json", ".toml", ".db", ".jsonl", ""))
    for blob in (*seen, caplog.text, stored):
        assert MODEL_KEY not in blob and MODEL_ENDPOINT not in blob
    approval = world.get_approval(approval_id)
    assert MODEL_KEY not in (approval.detail or "") and MODEL_KEY not in (approval.action or "")


def test_the_new_agent_page_and_the_agent_page_render(person, model):
    alice = person("alice")
    listing = alice.get("/factory")
    assert listing.status_code == 200 and "No agents yet" in listing.text and "New agent" in listing.text
    agent = agent_with_passing_tests(alice, model)
    page = alice.get(f"/factory/{agent['id']}")
    assert page.status_code == 200 and "Policy helper" in page.text and 'id="fx-editor"' in page.text and "second-shift-factory.js" in page.text
    assert alice.get("/factory").text.count("Policy helper") >= 1
    assert alice.get("/factory/FAC-nope").status_code == 404
    assert page.headers["cache-control"] == "private, no-store"
    assert "Lightwork" not in page.text and "Maverick" not in page.text and "Daybreak" not in page.text


def test_the_page_and_api_handle_a_record_that_cannot_be_read(person, model):
    assert person("alice").get("/api/v1/factory/agents/not-an-id").status_code == 404
    assert person("alice").get("/api/v1/factory/agents/FAC-" + "a" * 32).status_code == 404
