"""The model register: what it learns from agents, what people add, baselines,
checks, findings, and that no sample is ever kept."""
from __future__ import annotations

import random

import pytest

from maverick import agent_drift, agent_watch_changes, governed_records, model_drift, model_register
from maverick import external_agents as xa

ACTOR = "admin@corp.test"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_REPLICA_COUNT",
                 "MAVERICK_WORLD_BACKEND", "MAVERICK_AGENT_DRIFT"):
        monkeypatch.delenv(name, raising=False)
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    yield
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit_pkg
    rows: list[dict] = []

    def record(kind, *, agent="system", goal_id=None, **payload):
        rows.append({"kind": str(kind), "agent": agent, **payload})
        return True

    monkeypatch.setattr(audit_pkg, "record", record)
    return rows


@pytest.fixture
def alerts(monkeypatch):
    from maverick import ops_alert
    sent: list[dict] = []
    monkeypatch.setattr(ops_alert, "alert", lambda event, detail="", *, severity="high":
                        sent.append({"event": event, "detail": detail, "severity": severity}) or True)
    return sent


def _of(rows, kind):
    return [row for row in rows if row["kind"] == kind]


def _enroll(agent_id, **kw):
    return xa.enroll(agent_id, "agentforce", description=f"{agent_id} agent", owner="jordan@corp.test",
                     enrolled_by=ACTOR, **kw)


def _declare(agent_id, model, now=None):
    agent_drift.observe_run(agent_id, outcome="success", declared={"model": model}, now=now)


def _on_platform(agent_id, model, now=None):
    description = agent_watch_changes.describe("foundry", {"name": agent_id, "model": model})
    agent_drift.observe_discovered(agent_id, version_digest="d" * 40, source="foundry",
                                   description=description, now=now)


def _values(seed, n=400, mean=50.0, spread=10.0):
    rng = random.Random(seed)
    return [round(rng.gauss(mean, spread), 3) for _ in range(n)]


def _baseline(**extra):
    return {"numeric": {"age": _values(1)}, **extra}


def _ready(name="hand-model", **extra):
    """A hand-entered model with an approved baseline on one numeric feature."""
    made = model_register.add(name, actor=ACTOR)
    model_register.receive_samples(made["id"], _baseline(**extra), purpose="baseline", by=ACTOR)
    model_register.approve_baseline(made["id"], actor=ACTOR)
    return made["id"]


# ----------------------------------------------------------------- the register

def test_the_register_is_built_from_run_reports_and_platform_descriptions():
    for agent in ("alpha", "beta", "gamma", "delta"):
        _enroll(agent)
    _declare("alpha", "claude-sonnet", now=1000.0)
    _declare("beta", "claude-sonnet", now=2000.0)
    _on_platform("beta", "gpt-4o", now=3000.0)
    _on_platform("gamma", "gpt-4o", now=4000.0)
    _declare("delta", "m" * 150)  # not a name: kept by agents as a digest, never registered
    outcome = model_register.sync(now=5000.0)
    assert outcome == {"added": 2, "updated": 0, "problems": []}
    models = {m["name"]: m for m in model_register.list_models()}
    assert set(models) == {"claude-sonnet", "gpt-4o"}
    sonnet, gpt = models["claude-sonnet"], models["gpt-4o"]
    assert [a["id"] for a in sonnet["agents"]] == ["alpha", "beta"]
    assert {a["id"]: a["via"] for a in gpt["agents"]} == {"beta": ["platform check"], "gamma": ["platform check"]}
    assert sonnet["id"] == model_register.model_id("Claude-Sonnet")
    assert sonnet["first_seen"] == 1000.0 and sonnet["last_seen"] == 2000.0
    assert gpt["first_seen"] == 3000.0 and gpt["last_seen"] == 4000.0
    assert sonnet["status"] == "not_monitored" and sonnet["status_label"] == "No baseline yet"
    assert sonnet["hand_entered"] is False


def test_sync_writes_only_what_changed_and_follows_an_agent_to_a_new_model():
    _enroll("alpha")
    _declare("alpha", "model-one", now=1000.0)
    model_register.sync(now=2000.0)
    assert model_register.sync(now=2100.0) == {"added": 0, "updated": 0, "problems": []}
    _declare("alpha", "model-two", now=3000.0)
    assert model_register.sync(now=3100.0) == {"added": 1, "updated": 1, "problems": []}
    models = {m["name"]: m for m in model_register.list_models()}
    assert [(a["id"], a["current"]) for a in models["model-one"]["agents"]] == [("alpha", False)]
    assert [(a["id"], a["current"]) for a in models["model-two"]["agents"]] == [("alpha", True)]
    assert model_register.models_for_agent("alpha")[0]["name"] == "model-two"


def test_sync_says_so_when_an_agents_record_cannot_be_read(monkeypatch):
    _enroll("alpha")

    def broken(agent_id, **kw):
        raise agent_drift.AgentDriftStoreError("unreadable")

    monkeypatch.setattr(agent_drift, "detail", broken)
    outcome = model_register.sync()
    assert outcome["added"] == 0 and outcome["problems"] and "could not be read" in outcome["problems"][0]


def test_a_model_entered_by_hand_is_in_the_register_with_its_details():
    _enroll("alpha")
    made = model_register.add("Churn Scorer", actor=ACTOR, provider="In house", purpose="Ranks accounts at risk",
                              owner="data-science@corp.test", risk_tier="high", agents=["alpha"])
    assert made["hand_entered"] is True and made["risk_tier"] == "high"
    assert [(a["id"], a["via"]) for a in made["agents"]] == [("alpha", ["entered by hand"])]
    assert model_register.get(made["id"])["purpose"] == "Ranks accounts at risk"
    assert model_register.models_for_agent("alpha")[0]["name"] == "Churn Scorer"


@pytest.mark.parametrize("fields, fragment", [
    ({"name": ""}, "needed"),
    ({"name": "bad<name>"}, "letters, digits"),
    ({"name": "x", "risk_tier": "scary"}, "risk tier is one of"),
    ({"name": "x", "agents": ["nobody"]}, "not an agent added"),
    ({"name": "x", "agents": "alpha"}, "list"),
    ({"name": "x", "purpose": "key sk-ant-api03-" + "a" * 40}, "looks like a password or key"),
    ({"name": "x", "owner": "o" * 200}, "at most 120"),
])
def test_a_bad_hand_entry_is_refused(fields, fragment):
    name = fields.pop("name")
    with pytest.raises(model_register.ModelRegisterError, match=fragment):
        model_register.add(name, actor=ACTOR, **fields)
    assert model_register.list_models() == []


def test_the_same_name_is_one_model_however_it_is_cased():
    model_register.add("Churn Scorer", actor=ACTOR)
    with pytest.raises(model_register.ModelConflict, match="already in the register"):
        model_register.add("churn  scorer", actor=ACTOR)


def test_an_agent_reporting_a_hand_entered_name_joins_that_model():
    _enroll("alpha")
    made = model_register.add("claude-sonnet", actor=ACTOR, owner="ml@corp.test")
    _declare("alpha", "claude-sonnet")
    model_register.sync()
    (only,) = model_register.list_models()
    assert only["id"] == made["id"] and only["hand_entered"] is True and only["owner"] == "ml@corp.test"
    assert [a["id"] for a in only["agents"]] == ["alpha"]


def test_edit_changes_details_but_not_the_name_or_a_found_models_agents():
    _enroll("alpha")
    _declare("alpha", "model-one")
    model_register.sync()
    (found,) = model_register.list_models()
    edited = model_register.edit(found["id"], actor=ACTOR, owner="ml@corp.test", risk_tier="medium")
    assert (edited["owner"], edited["risk_tier"]) == ("ml@corp.test", "medium")
    with pytest.raises(model_register.ModelRegisterError, match="come from what the agents report"):
        model_register.edit(found["id"], actor=ACTOR, agents=["alpha"])
    with pytest.raises(model_register.ModelRegisterError, match="name cannot be changed"):
        model_register.edit(found["id"], actor=ACTOR, name="other")
    hand = model_register.add("by-hand", actor=ACTOR)
    assert model_register.edit(hand["id"], actor=ACTOR, agents=["alpha"])["agents"][0]["id"] == "alpha"
    with pytest.raises(model_register.ModelNotFound):
        model_register.edit("MDL-" + "0" * 20, actor=ACTOR, owner="x")


def test_registering_and_editing_are_audited(audit_rows):
    made = model_register.add("Churn Scorer", actor=ACTOR, risk_tier="low")
    model_register.edit(made["id"], actor=ACTOR, risk_tier="high")
    kinds = [r["kind"] for r in audit_rows if r["kind"].startswith("model_")]
    assert kinds == ["model_registered", "model_edited"]
    assert audit_rows[0]["actor"] == ACTOR and audit_rows[0]["model"] == "Churn Scorer"


def test_an_unknown_model_is_not_found_and_a_malformed_id_is_too():
    for bad in ("MDL-" + "0" * 20, "nonsense", "../x"):
        with pytest.raises(model_register.ModelNotFound):
            model_register.get(bad)


# ----------------------------------------------------------------------- baselines

def test_a_baseline_batch_waits_for_approval_and_checks_need_the_approved_one(audit_rows):
    made = model_register.add("m1", actor=ACTOR)
    with pytest.raises(model_register.ModelConflict, match="no approved baseline"):
        model_register.receive_samples(made["id"], _baseline(), purpose="check", by="op")
    out = model_register.receive_samples(made["id"], _baseline(), purpose="baseline", by="op@corp.test")
    assert out["awaiting_approval"] is True and out["candidate"]["signals"][0]["signal"] == "feature:age"
    waiting = model_register.get(made["id"])
    assert waiting["status"] == "awaiting_approval" and waiting["baseline"] is None
    with pytest.raises(model_register.ModelConflict, match="no approved baseline"):
        model_register.receive_samples(made["id"], _baseline(), purpose="check", by="op")
    approved = model_register.approve_baseline(made["id"], actor=ACTOR, now=123.0)
    assert approved["status"] == "monitored"
    got = model_register.get(made["id"])
    assert got["baseline"]["approved_by"] == ACTOR and got["baseline"]["received_by"] == "op@corp.test"
    assert got["candidate"] is None
    approvals = _of(audit_rows, "model_baseline_approved")
    assert len(approvals) == 1 and approvals[0]["approved_by"] == ACTOR
    assert len(_of(audit_rows, "model_baseline_received")) == 1


def test_approving_with_nothing_waiting_is_refused():
    made = model_register.add("m1", actor=ACTOR)
    with pytest.raises(model_register.ModelConflict, match="no baseline batch waiting"):
        model_register.approve_baseline(made["id"], actor=ACTOR)


def test_an_audit_refusal_stops_the_approval(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit.errors import AuditRefused
    made = model_register.add("m1", actor=ACTOR)
    model_register.receive_samples(made["id"], _baseline(), purpose="baseline", by="op")

    def refuse(*a, **k):
        raise AuditRefused("no")

    with monkeypatch.context() as patched:
        patched.setattr(audit_pkg, "record", refuse)
        with pytest.raises(AuditRefused):
            model_register.approve_baseline(made["id"], actor=ACTOR)
    assert model_register.get(made["id"])["baseline"] is None


def test_a_batch_that_cannot_be_used_is_refused_and_changes_nothing():
    made = model_register.add("m1", actor=ACTOR)
    with pytest.raises(model_drift.SampleError):
        model_register.receive_samples(made["id"], {"numeric": {"age": [1.0] * 3}}, purpose="baseline", by="op")
    assert model_register.get(made["id"])["candidate"] is None
    with pytest.raises(model_register.ModelRegisterError, match="baseline or for a check"):
        model_register.receive_samples(made["id"], _baseline(), purpose="train", by="op")


def test_checks_are_refused_while_model_drift_is_switched_off(tmp_path):
    from maverick import config
    made = model_register.add("m1", actor=ACTOR)
    (tmp_path / "config.toml").write_text("[model_drift]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    with pytest.raises(model_register.ModelConflict, match="turned off"):
        model_register.receive_samples(made["id"], _baseline(), purpose="baseline", by="op")


# ------------------------------------------------------------------ findings

_DEFAULTS = model_drift.settings()


def _only(**overrides):
    """Settings with every threshold out of reach except the ones given."""
    return {**_DEFAULTS, "psi_threshold": 10.0, "js_threshold": 1.0, "chi2_p_value_floor": 0.0,
            "ks_p_value_floor": 0.0, "embedding_cosine_threshold": 2.0, "accuracy_decay_threshold": 1.0,
            **overrides}


_SHIFTED = {"numeric": {"age": _values(7, mean=62.0)}}
_MILD = {"numeric": {"age": _values(7, mean=55.0)}}
_CASES = {
    "psi": ({"psi_threshold": 0.2}, "feature:age:psi", {}, _SHIFTED),
    "js": ({"js_threshold": 0.1}, "feature:age:js", {}, _SHIFTED),
    "chi2": ({"chi2_p_value_floor": 0.5}, "feature:age:chi2", {}, _SHIFTED),
    "ks": ({"ks_p_value_floor": 0.5}, "feature:age:ks", {}, _SHIFTED),
    "cosine": ({"embedding_cosine_threshold": 0.1}, "embedding:cosine",
               {"embeddings": [[1.0, 0.0]] * 40}, {"embeddings": [[1.0, 1.0]] * 40}),
    "decay": ({"accuracy_decay_threshold": 0.05}, "accuracy:decay",
              {"predictions": [0, 1] * 100, "labels": [0, 1] * 100},
              {"predictions": [0, 1] * 50, "labels": [0, 1] * 40 + [1, 0] * 10}),
}


@pytest.mark.parametrize("case", sorted(_CASES))
def test_a_check_crossing_one_threshold_makes_one_finding_audited_and_alerted_once(case, monkeypatch, audit_rows, alerts):
    overrides, key, extra_baseline, batch = _CASES[case]
    monkeypatch.setattr(model_drift, "settings", lambda: _only(**overrides))
    model = _ready(**extra_baseline)
    audit_rows.clear()
    first = model_register.receive_samples(model, batch, purpose="check", by="op@corp.test")
    assert [f["key"] for f in first["findings"]] == [key] and first["new_findings"] == [key]
    assert len(_of(audit_rows, "model_drift_detected")) == 1 and len(alerts) == 1
    row, = _of(audit_rows, "model_drift_detected")
    assert row["finding"] == key and row["model"] == "hand-model" and row["summary"]
    assert alerts[0]["event"] == "model_drift.detected" and "hand-model" in alerts[0]["detail"]
    # the same finding is listed again but neither audited nor alerted a second time
    again = model_register.receive_samples(model, batch, purpose="check", by="op@corp.test")
    assert [f["key"] for f in again["findings"]] == [key] and again["new_findings"] == []
    assert len(_of(audit_rows, "model_drift_detected")) == 1 and len(alerts) == 1
    got = model_register.get(model)
    assert got["status"] == "drifting" and got["open_findings"] == 1 and len(got["checks"]) == 2


def test_a_check_inside_every_threshold_makes_no_finding(audit_rows, alerts):
    model = _ready()
    out = model_register.receive_samples(model, {"numeric": {"age": _values(8)}}, purpose="check", by="op")
    assert out["findings"] == [] and out["new_findings"] == []
    assert _of(audit_rows, "model_drift_detected") == [] and alerts == []
    got = model_register.get(model)
    assert got["status"] == "monitored" and got["last_check_at"] and got["checks"][0]["max_psi"] is not None


def test_several_findings_in_one_check_send_one_alert(audit_rows, alerts):
    model = _ready()
    out = model_register.receive_samples(model, {"numeric": {"age": _values(7, mean=75.0)}}, purpose="check", by="op")
    assert len(out["new_findings"]) >= 3
    assert len(_of(audit_rows, "model_drift_detected")) == len(out["new_findings"])
    assert len(alerts) == 1 and "more finding" in alerts[0]["detail"] and alerts[0]["severity"] == "high"


def test_a_finding_that_gets_worse_is_reported_again(audit_rows, alerts, monkeypatch):
    monkeypatch.setattr(model_drift, "settings", lambda: _only(psi_threshold=0.2))
    model = _ready()
    first = model_register.receive_samples(model, {"numeric": {"age": _values(7, mean=55.0)}}, purpose="check", by="op")
    assert [f["severity"] for f in first["findings"]] == ["medium"]
    second = model_register.receive_samples(model, {"numeric": {"age": _values(7, mean=80.0)}}, purpose="check", by="op")
    assert [f["severity"] for f in second["findings"]] == ["high"] and second["new_findings"] == ["feature:age:psi"]
    assert len(_of(audit_rows, "model_drift_detected")) == 2 and len(alerts) == 2


def test_acknowledging_a_finding(audit_rows, alerts, monkeypatch):
    monkeypatch.setattr(model_drift, "settings", lambda: _only(psi_threshold=0.2))
    model = _ready()
    model_register.receive_samples(model, _MILD, purpose="check", by="op")
    out = model_register.acknowledge(model, "feature:age:psi", actor="lead@corp.test")
    assert out["acknowledged_by"] == "lead@corp.test"
    got = model_register.get(model)
    assert got["findings"][0]["acknowledged"] is True and got["findings"][0]["acknowledged_by"] == "lead@corp.test"
    assert got["status"] == "monitored" and got["open_findings"] == 0
    ack, = _of(audit_rows, "model_drift_acknowledged")
    assert ack["acknowledged_by"] == "lead@corp.test" and ack["finding"] == "feature:age:psi"
    with pytest.raises(model_register.ModelNotFound, match="no open finding"):
        model_register.acknowledge(model, "feature:age:psi", actor="lead@corp.test")
    with pytest.raises(model_register.ModelNotFound):
        model_register.acknowledge(model, "feature:age:nonsense", actor="lead@corp.test")
    # an acknowledged finding that comes again is neither alerted nor open
    before = len(alerts)
    again = model_register.receive_samples(model, _MILD, purpose="check", by="op")
    assert again["findings"][0]["acknowledged"] is True and again["new_findings"] == [] and len(alerts) == before
    assert model_register.get(model)["status"] == "monitored"
    # one that gets worse is open again
    worse = model_register.receive_samples(model, {"numeric": {"age": _values(7, mean=62.0)}}, purpose="check", by="op")
    assert worse["findings"][0]["acknowledged"] is False and worse["new_findings"] == ["feature:age:psi"]


def test_a_new_baseline_ends_the_old_findings():
    model = _ready()
    model_register.receive_samples(model, _SHIFTED, purpose="check", by="op")
    assert model_register.get(model)["status"] == "drifting"
    model_register.receive_samples(model, _SHIFTED, purpose="baseline", by="op")
    model_register.approve_baseline(model, actor=ACTOR)
    got = model_register.get(model)
    assert got["status"] == "monitored" and got["findings"] == [] and len(got["checks"]) == 1


def test_checks_are_bounded_to_the_newest_thirty():
    model = _ready()
    for seed in range(35):
        model_register.receive_samples(model, {"numeric": {"age": _values(seed + 20)}}, purpose="check", by="op")
    assert len(model_register.get(model)["checks"]) == 30


def test_findings_reach_the_agents_that_use_the_model_and_the_home_page(monkeypatch):
    monkeypatch.setattr(model_drift, "settings", lambda: _only(psi_threshold=0.2))
    _enroll("alpha")
    _enroll("beta")
    made = model_register.add("Churn Scorer", actor=ACTOR, agents=["alpha"])
    model_register.receive_samples(made["id"], _baseline(), purpose="baseline", by="op")
    model_register.approve_baseline(made["id"], actor=ACTOR)
    model_register.receive_samples(made["id"], _SHIFTED, purpose="check", by="op")
    (finding,) = model_register.findings_for_agent("alpha")
    assert finding["model_id"] == made["id"] and finding["key"] == "feature:age:psi"
    assert model_register.findings_for_agent("beta") == []
    items, count = model_register.home_items()
    assert count == 1 and items[0]["href"] == f"/models/{made['id']}#model-findings"
    assert items[0]["text"].startswith("Churn Scorer: ") and items[0]["severity"] in ("medium", "high")
    model_register.acknowledge(made["id"], "feature:age:psi", actor=ACTOR)
    assert model_register.home_items() == ([], 0)
    assert model_register.findings_for_agent("alpha") == []


# --------------------------------------------------------------- no samples kept

def test_samples_are_never_written_anywhere(tmp_path):
    model = _ready()
    numeric_marker, category_marker = 98765.4321, "zz-marker-category"
    sample = _values(3)
    sample[17] = numeric_marker
    labels = ["red"] * 200 + ["blue"] * 199 + [category_marker]
    batch = {"numeric": {"age": sample}, "categorical": {"colour": labels},
             "predictions": ["yes"] * 200 + ["no"] * 200}
    model_register.receive_samples(model, batch, purpose="check", by="op")
    made = model_register.add("second", actor=ACTOR)
    model_register.receive_samples(made["id"], batch, purpose="baseline", by="op")
    model_register.approve_baseline(made["id"], actor=ACTOR)
    found = []
    for path in tmp_path.rglob("*"):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        if path.suffix in (".db", ".sqlite"):
            blob += b"".join(str(row).encode() for row in _dump(path))
        for marker in (str(numeric_marker), category_marker, "98765"):
            if marker.encode() in blob:
                found.append((path.name, marker))
    assert found == []
    # and the register holds only the aggregates
    record = model_register.get(made["id"])
    assert [s["signal"] for s in record["baseline"]["signals"]] == ["feature:age", "feature:colour", "prediction"]
    assert sum(1 for p in tmp_path.rglob("*") if p.is_file() and p.suffix == ".json") >= 1


def _dump(path):
    import sqlite3
    try:
        con = sqlite3.connect(path)
        try:
            for (name,) in con.execute("select name from sqlite_master where type='table'").fetchall():
                yield from con.execute(f'select * from "{name}"').fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return


def test_a_stored_record_is_small_however_big_the_batch_was(tmp_path):
    made = model_register.add("m1", actor=ACTOR)
    big = {"numeric": {f"f{i}": _values(i, n=1200) for i in range(14)}, "predictions": _values(99, n=1200)}
    model_register.receive_samples(made["id"], big, purpose="baseline", by="op")
    sizes = [p.stat().st_size for p in tmp_path.rglob("MDL-*.json")]
    assert sizes and max(sizes) < 40_000
