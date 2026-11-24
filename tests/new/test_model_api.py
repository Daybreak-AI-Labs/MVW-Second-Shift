"""The model register API, the Models pages and where findings show: each
permission level, an outside agent's own key, bounded batches, and escaping.

Hermetic. Each person signs in as in ``signin_kit``; every answer comes from the
real routes of the web app."""
from __future__ import annotations

import random

import pytest
from fastapi.testclient import TestClient

from tests.new import signin_kit as kit
from tests.new.signin_kit import ROLES

OPERATE = {"admin", "governance_lead", "operator"}
RESPOND = OPERATE | {"responder"}
PURPOSE = "Ranks <script>alert(1)</script> accounts"


@pytest.fixture(scope="module")
def signing_key():
    return kit.new_key()


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch, request, signing_key):
    from maverick import governed_records

    governed_records._reset_process_authority_pin_for_testing()
    stop = kit.start(tmp_path, monkeypatch, request, signing_key)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_REPLICA_COUNT",
                 "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    from maverick_dashboard import models_api
    models_api._rate_times.clear()
    yield tmp_path
    models_api._rate_times.clear()
    governed_records._reset_process_authority_pin_for_testing()
    stop()


@pytest.fixture
def app():
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def person(app, signing_key):
    def client(role: str) -> TestClient:
        return kit.client_for(app, signing_key, role)
    return client


def _values(seed, n=300, mean=50.0, spread=10.0):
    rng = random.Random(seed)
    return [round(rng.gauss(mean, spread), 3) for _ in range(n)]


def _batch(purpose="baseline", seed=1, mean=50.0, **extra):
    return {"purpose": purpose, "numeric": {"age": _values(seed, mean=mean)}, **extra}


def _model(person, name="Churn Scorer", **fields):
    made = person("admin").post("/api/v1/models", json={"name": name, **fields})
    assert made.status_code == 201, made.text
    return made.json()["id"]


def _ready(person, name="Churn Scorer", **fields):
    model = _model(person, name, **fields)
    assert person("operator").post(f"/api/v1/models/{model}/samples", json=_batch()).status_code == 200
    assert person("admin").post(f"/api/v1/models/{model}/baseline/approve").status_code == 200
    return model


def _agent(person, app, agent_id="helpdesk"):
    admin = person("admin")
    made = admin.post("/api/v1/external-agents", json={"id": agent_id, "platform": "copilot", "owner": "ops@example.com"})
    assert made.status_code == 201, made.text
    minted = admin.post(f"/api/v1/external-agents/{agent_id}/credentials", json={"surface": "rest"})
    assert minted.status_code == 200, minted.text
    return TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {minted.json()['token']}"})


# ---------------------------------------------------------------- permissions

@pytest.mark.parametrize("role", ROLES)
def test_each_role_gets_exactly_the_access_its_permissions_give(role, person):
    me = person(role)
    assert me.get("/api/v1/models").status_code == 200
    assert me.get("/models").status_code == 200
    # adding a model is administration
    added = me.post("/api/v1/models", json={"name": f"by-{role}"})
    assert added.status_code == (201 if role == "admin" else 403)
    model = _model(person, f"made-for-{role}")
    assert me.get(f"/api/v1/models/{model}").status_code == 200
    assert me.patch(f"/api/v1/models/{model}", json={"owner": "x@corp.test"}).status_code == (200 if role == "admin" else 403)
    # samples are day-to-day work
    sent = me.post(f"/api/v1/models/{model}/samples", json=_batch())
    assert sent.status_code == (200 if role in OPERATE else 403), sent.text
    # approving what a person sent is administration
    approved = me.post(f"/api/v1/models/{model}/baseline/approve")
    assert approved.status_code in ((200, 409) if role == "admin" else (403,))
    ack = me.post(f"/api/v1/models/{model}/findings/acknowledge", json={"finding": "feature:age:psi"})
    assert ack.status_code == (404 if role in RESPOND else 403)


def test_baseline_approval_is_administration_only(person):
    model = _model(person)
    assert person("operator").post(f"/api/v1/models/{model}/samples", json=_batch()).status_code == 200
    for role in ("operator", "governance_lead", "responder", "viewer"):
        assert person(role).post(f"/api/v1/models/{model}/baseline/approve").status_code == 403
    assert person("admin").get(f"/api/v1/models/{model}").json()["status"] == "awaiting_approval"
    assert person("admin").post(f"/api/v1/models/{model}/baseline/approve").status_code == 200
    assert person("viewer").get(f"/api/v1/models/{model}").json()["status"] == "monitored"


def test_nobody_without_a_sign_in_reaches_anything(app):
    bare = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert bare.get("/api/v1/models").status_code in (401, 403)
    assert bare.post("/api/v1/models", json={"name": "x"}).status_code in (401, 403)


# ----------------------------------------------------------------------- flow

def test_a_model_goes_from_baseline_to_a_finding_to_an_acknowledgement(person, app):
    model = _ready(person, purpose=PURPOSE, owner="ml@corp.test", risk_tier="high")
    operator, responder, viewer = person("operator"), person("responder"), person("viewer")
    clean = operator.post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=9)).json()
    assert clean["findings"] == [] and clean["compared"] == ["feature:age"]
    drifted = operator.post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=9, mean=65.0)).json()
    assert "feature:age:psi" in drifted["new_findings"]
    repeat = operator.post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=9, mean=65.0)).json()
    assert repeat["new_findings"] == []
    got = viewer.get(f"/api/v1/models/{model}").json()
    assert got["status"] == "drifting" and got["open_findings"] >= 3 and len(got["checks"]) == 3
    listed = viewer.get("/api/v1/models").json()
    assert listed["enabled"] is True and [m["name"] for m in listed["models"]] == ["Churn Scorer"]
    acked = responder.post(f"/api/v1/models/{model}/findings/acknowledge", json={"finding": "feature:age:psi"})
    assert acked.status_code == 200 and acked.json()["acknowledged_by"] == "user:responder"
    assert responder.post(f"/api/v1/models/{model}/findings/acknowledge", json={"finding": "feature:age:psi"}).status_code == 404


def test_the_answer_to_a_batch_holds_statistics_and_no_sample(person):
    model = _model(person)
    marker = 31337.31337
    values = _values(4)
    values[3] = marker
    sent = person("operator").post(f"/api/v1/models/{model}/samples", json={"purpose": "baseline", "numeric": {"x": values}})
    assert sent.status_code == 200 and str(marker) not in sent.text
    assert str(marker) not in person("viewer").get(f"/api/v1/models/{model}").text


def test_a_check_before_a_baseline_and_an_unknown_model_are_plain_refusals(person):
    model = _model(person)
    early = person("operator").post(f"/api/v1/models/{model}/samples", json=_batch("check"))
    assert early.status_code == 409 and "no approved baseline" in early.json()["detail"]
    for bad in ("MDL-" + "0" * 20, "nonsense"):
        assert person("viewer").get(f"/api/v1/models/{bad}").status_code == 404
        assert person("operator").post(f"/api/v1/models/{bad}/samples", json=_batch()).status_code == 404


def test_a_hand_entry_can_be_changed_and_the_name_stays(person):
    model = _model(person, owner="a@corp.test")
    admin = person("admin")
    assert admin.post("/api/v1/models", json={"name": "churn   scorer"}).status_code == 409
    assert admin.patch(f"/api/v1/models/{model}", json={"owner": "b@corp.test", "risk_tier": "low"}).json()["owner"] == "b@corp.test"
    assert admin.patch(f"/api/v1/models/{model}", json={"name": "Other"}).status_code == 422
    assert admin.patch(f"/api/v1/models/{model}", json={"owner": None}).status_code == 422
    assert admin.post("/api/v1/models", json={"name": "z", "agents": ["nobody"]}).status_code == 422
    assert admin.post("/api/v1/models", json={"name": "z", "risk_tier": "scary"}).status_code == 422
    assert admin.post("/api/v1/models", json={"name": "z", "surprise": 1}).status_code == 422


# ------------------------------------------------------------------- bounds

@pytest.mark.parametrize("body, fragment", [
    ({"purpose": "baseline", "surprise": 1}, "surprise is not something"),
    ({"purpose": "train"}, "purpose is not valid"),
    ({"numeric": {"x": []}}, "purpose is needed"),
    ({"purpose": "baseline", "numeric": {"x": ["SECRETVALUE"] * 40}}, "not valid"),
    ({"purpose": "baseline", "numeric": {"x": [1] * 5001}}, "not valid"),
    ({"purpose": "baseline", "numeric": {f"f{i}": [1.0] * 40 for i in range(17)}}, "not valid"),
    ({"purpose": "baseline", "categorical": {"x": [1, 2, 3]}}, "not valid"),
    ({"purpose": "baseline", "embeddings": [[1.0] * 257] * 40}, "not valid"),
    ({"purpose": "baseline", "embeddings": [[1.0]] * 201}, "not valid"),
    ({"purpose": "baseline", "numeric": {"x": [1.0] * 5}}, "at least 30"),
    ({"purpose": "baseline"}, "at least one"),
    ({"purpose": "baseline", "numeric": {"x": [1.0] * 40}, "extra": {"a": 1}}, "extra is not something"),
])
def test_a_batch_that_breaks_a_bound_or_has_an_unknown_field_is_refused(person, body, fragment):
    model = _model(person)
    out = person("operator").post(f"/api/v1/models/{model}/samples", json=body)
    assert out.status_code == 422, out.text
    assert fragment in out.json()["detail"]
    assert "SECRETVALUE" not in out.text
    assert person("admin").get(f"/api/v1/models/{model}").json()["candidate"] is None


def test_too_many_values_in_all_and_a_huge_body_are_refused(person):
    model = _model(person)
    spread = {"purpose": "baseline", "numeric": {f"f{i}": [1.0] * 2000 for i in range(11)}}
    out = person("operator").post(f"/api/v1/models/{model}/samples", json=spread)
    assert out.status_code in (413, 422)
    huge = person("operator").post(f"/api/v1/models/{model}/samples", content=b"[" + b"1," * 300_000 + b"1]",
                                   headers={"Content-Type": "application/json"})
    assert huge.status_code == 413
    broken = person("operator").post(f"/api/v1/models/{model}/samples", content=b"{nope",
                                     headers={"Content-Type": "application/json"})
    assert broken.status_code == 422


def test_batches_are_rate_limited_for_each_caller_and_model(person, tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text("[model_drift]\nbatches_per_minute = 2\n", encoding="utf-8")
    config.reset_config_cache()
    model, other = _model(person), _model(person, "Other Model")
    operator = person("operator")
    codes = [operator.post(f"/api/v1/models/{model}/samples", json=_batch()).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    refused = operator.post(f"/api/v1/models/{model}/samples", json=_batch())
    assert "At most 2 batches a minute" in refused.json()["detail"] and refused.headers["Retry-After"] == "60"
    assert operator.post(f"/api/v1/models/{other}/samples", json=_batch()).status_code == 200
    assert person("governance_lead").post(f"/api/v1/models/{model}/samples", json=_batch()).status_code == 200


# --------------------------------------------------------------- an agent's key

def test_an_agent_may_send_samples_only_for_a_model_its_agent_uses(person, app):
    mine = _agent(person, app, "helpdesk")
    other = _agent(person, app, "payroll")
    model = _model(person, "Helpdesk Model", agents=["helpdesk"])
    elsewhere = _model(person, "Payroll Model", agents=["payroll"])
    assert [m["id"] for m in mine.get("/api/v1/external/models").json()["models"]] == [model]
    sent = mine.post(f"/api/v1/external/models/{model}/samples", json=_batch())
    assert sent.status_code == 200 and sent.json()["awaiting_approval"] is True
    assert other.post(f"/api/v1/external/models/{model}/samples", json=_batch()).status_code == 403
    assert mine.post(f"/api/v1/external/models/{elsewhere}/samples", json=_batch()).status_code == 403
    assert mine.post("/api/v1/external/models/MDL-" + "0" * 20 + "/samples", json=_batch()).status_code == 403
    got = person("viewer").get(f"/api/v1/models/{model}").json()
    assert got["candidate"]["received_by"] == "agent:helpdesk"
    person("admin").post(f"/api/v1/models/{model}/baseline/approve")
    assert mine.post(f"/api/v1/external/models/{model}/samples", json=_batch("check", seed=5)).json()["findings"] == []


def test_an_agent_that_reports_its_model_can_send_samples_for_it(person, app):
    agent = _agent(person, app)
    run = agent.post("/api/v1/external/runs", json={"title": "Reset a password", "outcome": "success",
                                                    "declared": {"model": "claude-sonnet"}})
    assert run.status_code == 201, run.text
    (model,) = agent.get("/api/v1/external/models").json()["models"]
    assert model["name"] == "claude-sonnet"
    assert agent.post(f"/api/v1/external/models/{model['id']}/samples", json=_batch()).status_code == 200
    assert person("viewer").get("/api/v1/models").json()["models"][0]["agents"][0]["via"] == ["run report"]


def test_an_agents_key_opens_nothing_else_and_a_stranger_opens_nothing(person, app):
    mine = _agent(person, app)
    model = _model(person, agents=["helpdesk"])
    assert mine.get("/api/v1/models").status_code in (401, 403)
    assert mine.post(f"/api/v1/models/{model}/samples", json=_batch()).status_code in (401, 403)
    assert mine.post(f"/api/v1/models/{model}/baseline/approve").status_code in (401, 403)
    stranger = TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer ss-rest-nope"})
    assert stranger.get("/api/v1/external/models").status_code == 401
    assert stranger.post(f"/api/v1/external/models/{model}/samples", json=_batch()).status_code == 401
    unknown = mine.post(f"/api/v1/external/models/{model}/samples", json={**_batch(), "surprise": 1})
    assert unknown.status_code == 422


# -------------------------------------------------------------------- pages

def test_the_pages_escape_everything_a_person_wrote(person):
    model = _ready(person, purpose=PURPOSE, owner="<img src=x onerror=alert(1)>", provider="<b>Acme</b>")
    person("operator").post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=9, mean=65.0))
    listing = person("viewer").get("/models")
    assert listing.status_code == 200 and "Churn Scorer" in listing.text
    detail = person("viewer").get(f"/models/{model}")
    assert detail.status_code == 200
    for page in (listing.text, detail.text):
        assert "<script>alert(1)</script>" not in page and "<img src=x" not in page and "<b>Acme</b>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail.text
    assert "\\u003cscript\\u003e" in detail.text  # inside the page's own script, as data


def test_the_model_page_shows_the_baseline_the_checks_and_a_plain_svg_chart(person):
    model = _ready(person)
    for seed, mean in ((9, 50.0), (10, 52.0), (11, 65.0)):
        person("operator").post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=seed, mean=mean))
    page = person("viewer").get(f"/models/{model}").text
    assert "Changed from its baseline" in page and "Recent checks" in page
    chart = page.split('id="model-chart"')[1].split("</svg>")[0]
    assert "<polyline" in chart and "stroke-dasharray" in chart and chart.count("<circle") == 3
    assert 'data-model-ack="feature:age:psi"' in page
    assert "Feature: <strong>age</strong>" in page
    assert "http" not in chart and "<script" not in chart  # plain SVG: no library, no address


def test_a_viewer_sees_buttons_that_are_switched_off(person):
    model = _ready(person)
    person("operator").post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=9, mean=65.0))
    page = person("viewer").get(f"/models/{model}").text
    assert 'id="model-edit" disabled aria-disabled="true"' in page
    assert "Only an administrator can change a model" in page
    assert "model-samples" not in page  # the way to send samples is for people who can


def test_an_unknown_model_page_is_not_found(person):
    assert person("viewer").get("/models/MDL-" + "0" * 20).status_code == 404
    assert person("viewer").get("/models/not-an-id").status_code == 404


def test_findings_show_on_the_agent_page_and_on_home(person, app):
    _agent(person, app)
    model = _ready(person, agents=["helpdesk"])
    person("operator").post(f"/api/v1/models/{model}/samples", json=_batch("check", seed=9, mean=65.0))
    agent_page = person("viewer").get("/external-agents/helpdesk").text
    assert 'id="model-drift"' in agent_page and f"/models/{model}#model-findings" in agent_page
    home = person("viewer").get("/").text
    assert "Churn Scorer: " in home and f"/models/{model}#model-findings" in home
    person("responder").post(f"/api/v1/models/{model}/findings/acknowledge", json={"finding": "feature:age:psi"})
    # one acknowledged; the others are still open
    assert person("viewer").get(f"/api/v1/models/{model}").json()["open_findings"] >= 2


def test_the_register_page_lists_models_found_from_agents(person, app):
    agent = _agent(person, app)
    agent.post("/api/v1/external/runs", json={"title": "t", "outcome": "success", "declared": {"model": "gpt-4o"}})
    page = person("viewer").get("/models").text
    assert "gpt-4o" in page and "helpdesk" in page and "No baseline yet" in page


def test_models_is_in_the_navigation_for_everyone_who_can_view(person):
    page = person("viewer").get("/models").text
    assert 'href="/models"' in page
