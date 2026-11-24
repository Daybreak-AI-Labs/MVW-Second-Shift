"""Drift detection for outside agents: the statistics, the settings, the
rolling record, baselines, findings, reactions and the gateway hooks."""
from __future__ import annotations

import json
import math
import os

import pytest

from maverick import agent_drift as drift
from maverick import external_agents as xa

DAY = 86400
#: Midnight UTC on a fixed day; every test places its activity relative to it.
T0 = 20_000 * DAY
AGENT = "sf-quotebot"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    # These tests judge findings straight after approving a baseline; the
    # learning period has its own tests (test_defaults_learning_period.py).
    monkeypatch.setitem(drift._NUMBER_SETTINGS, "learning_days", (int, 0, 0, 365))
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _configure(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config
    config.reset_config_cache()


# ---------------------------------------------------------------- statistics

def test_js_divergence_is_zero_for_the_same_mix_at_any_scale():
    mix = {"crm_update": 6, "research": 3, "send_contract": 1}
    assert drift.js_divergence(mix, mix) == pytest.approx(0.0, abs=1e-12)
    scaled = {tool: count * 50 for tool, count in mix.items()}
    assert drift.js_divergence(mix, scaled) == pytest.approx(0.0, abs=1e-12)


def test_js_divergence_is_one_for_mixes_with_nothing_in_common():
    assert drift.js_divergence({"a": 5}, {"b": 9}) == pytest.approx(1.0)
    assert drift.js_divergence({"a": 1, "b": 1}, {"c": 4, "d": 4}) == pytest.approx(1.0)


def test_js_divergence_is_symmetric_and_bounded():
    left = {"a": 50, "b": 50}
    right = {"a": 90, "b": 10}
    forward = drift.js_divergence(left, right)
    assert forward == pytest.approx(drift.js_divergence(right, left))
    assert 0.0 < forward < 1.0
    # Worked by hand: KL(P||M) = 0.1258, KL(Q||M) = 0.1679, mean = 0.1468 bits.
    assert forward == pytest.approx(0.1468, abs=5e-4)


def test_js_divergence_ignores_junk_counts_and_an_empty_side():
    assert drift.js_divergence({}, {"a": 3}) == 0.0
    assert drift.js_divergence({"a": 3}, {}) == 0.0
    assert drift.js_divergence({"a": 0, "b": -4}, {"a": 3}) == 0.0
    noisy = {"a": 5, "b": 0, "c": -2, "d": float("nan"), "e": "many"}
    assert drift.js_divergence(noisy, {"a": 1}) == pytest.approx(0.0, abs=1e-12)


def test_change_ratio_compares_current_with_baseline():
    assert drift.change_ratio(10, 30) == pytest.approx(3.0)
    assert drift.change_ratio(10, 2.5) == pytest.approx(0.25)
    assert drift.change_ratio(4, 4) == pytest.approx(1.0)


def test_change_ratio_handles_a_zero_baseline():
    assert drift.change_ratio(0, 0) == 1.0
    assert drift.change_ratio(0, 5) == math.inf
    # A floor keeps tiny amounts from reading as a huge change.
    assert drift.change_ratio(0.0, 0.004, floor=0.01) == 1.0
    assert drift.change_ratio(0.0, 0.12, floor=0.01) == pytest.approx(12.0)
    assert drift.change_ratio(0.5, 0.0, floor=0.01) == pytest.approx(0.02)


def test_share_is_zero_when_there_is_nothing_to_divide_by():
    assert drift.share(3, 12) == pytest.approx(0.25)
    assert drift.share(0, 12) == 0.0
    assert drift.share(5, 0) == 0.0
    assert drift.share(9, 3) == 1.0  # never more than the whole


# ------------------------------------------------------------------ settings

def test_settings_defaults():
    cfg = drift.settings()
    assert cfg["enable"] is True
    assert cfg["baseline_days"] == 14
    assert cfg["window_days"] == 3
    assert cfg["on_drift"] == "alert"
    assert cfg["min_runs"] >= 1 and cfg["min_screens"] >= 1
    for name in ("volume_ratio", "cost_ratio"):
        assert cfg[name] > 1.0
    for name in ("tool_mix_threshold", "denial_rate_rise", "failure_rate_rise"):
        assert 0.0 < cfg[name] <= 1.0


def test_settings_read_the_agent_drift_section(tmp_path):
    _configure(tmp_path, "[agent_drift]\nbaseline_days = 7\nwindow_days = 2\n"
                         "min_runs = 9\nvolume_ratio = 4.5\non_drift = \"contain\"\n")
    cfg = drift.settings()
    assert (cfg["baseline_days"], cfg["window_days"], cfg["min_runs"]) == (7, 2, 9)
    assert cfg["volume_ratio"] == pytest.approx(4.5)
    assert cfg["on_drift"] == "contain"


@pytest.mark.parametrize("line, name, expected", [
    ("baseline_days = 0", "baseline_days", 1),
    ("baseline_days = 4000", "baseline_days", 30),
    ("window_days = -3", "window_days", 1),
    ("window_days = 365", "window_days", 7),
    ("min_runs = 0", "min_runs", 1),
    ("min_runs = 99999999", "min_runs", 1000),
    ("min_screens = -1", "min_screens", 1),
    ("tool_mix_min_samples = 1", "tool_mix_min_samples", 5),
    ("volume_ratio = 1.0", "volume_ratio", 1.1),
    ("volume_ratio = 1e9", "volume_ratio", 100.0),
    ("cost_ratio = 0.0", "cost_ratio", 1.1),
    ("tool_mix_threshold = 0.0", "tool_mix_threshold", 0.01),
    ("tool_mix_threshold = 7", "tool_mix_threshold", 1.0),
    ("denial_rate_rise = -0.5", "denial_rate_rise", 0.01),
    ("failure_rate_rise = 3.0", "failure_rate_rise", 1.0),
])
def test_settings_clamp_out_of_range_values(tmp_path, line, name, expected):
    _configure(tmp_path, f"[agent_drift]\n{line}\n")
    assert drift.settings()[name] == pytest.approx(expected)


@pytest.mark.parametrize("line, name", [
    ('baseline_days = "fourteen"', "baseline_days"),
    ("baseline_days = true", "baseline_days"),
    ("window_days = 2.5", "window_days"),
    ("min_runs = [5]", "min_runs"),
    ("volume_ratio = nan", "volume_ratio"),
    ("cost_ratio = inf", "cost_ratio"),
    ('denial_rate_rise = "a lot"', "denial_rate_rise"),
    ('on_drift = "delete-the-agent"', "on_drift"),
    ("on_drift = 1", "on_drift"),
    ("on_drift = [\"contain\"]", "on_drift"),
    ('enable = "no"', "enable"),
    ("enable = 0", "enable"),
])
def test_settings_fall_back_to_the_default_for_a_malformed_value(tmp_path, line, name):
    defaults = drift.settings()
    _configure(tmp_path, f"[agent_drift]\n{line}\n")
    assert drift.settings()[name] == defaults[name]


@pytest.mark.parametrize("body", [
    "agent_drift = 7\n",
    "agent_drift = \"contain\"\n",
    "[agent_drift]\non_drift = \"contain\"\nthis is not toml\n",
])
def test_settings_fall_back_to_safe_defaults_for_a_malformed_section(tmp_path, body):
    defaults = drift.settings()
    _configure(tmp_path, body)
    assert drift.settings() == defaults
    assert drift.settings()["on_drift"] == "alert"


def test_settings_survive_a_config_loader_that_raises(monkeypatch):
    defaults = drift.settings()
    from maverick import config

    def unavailable(*_a, **_kw):
        raise RuntimeError("configuration backend unavailable")

    monkeypatch.setattr(config, "load_config", unavailable)
    assert drift.settings() == defaults


def test_on_drift_is_read_case_insensitively(tmp_path):
    _configure(tmp_path, "[agent_drift]\non_drift = \" Contain \"\n")
    assert drift.settings()["on_drift"] == "contain"


def test_enabled_follows_outside_agent_governance(monkeypatch):
    assert drift.enabled() is True
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert drift.enabled() is False


def test_enabled_honours_config_and_the_environment_switch(tmp_path, monkeypatch):
    _configure(tmp_path, "[agent_drift]\nenable = false\n")
    assert drift.enabled() is False
    monkeypatch.setenv("MAVERICK_AGENT_DRIFT", "1")
    assert drift.enabled() is True
    _configure(tmp_path, "[agent_drift]\nenable = true\n")
    monkeypatch.setenv("MAVERICK_AGENT_DRIFT", "0")
    assert drift.enabled() is False
    # A value that is neither on nor off leaves the configured setting alone.
    monkeypatch.setenv("MAVERICK_AGENT_DRIFT", "maybe")
    assert drift.enabled() is True


def test_the_comparison_window_is_never_longer_than_the_baseline(tmp_path):
    _configure(tmp_path, "[agent_drift]\nbaseline_days = 2\nwindow_days = 5\n")
    cfg = drift.settings()
    assert (cfg["baseline_days"], cfg["window_days"]) == (2, 2)


# ------------------------------------------------------------------- helpers

_TOOLS = ["crm_update:low", "research:low", "send_contract:high", "wire_transfer"]
#: A normal day: 10 runs at $0.50, one failed; 20 screened actions, one refused.
_NORMAL = {"runs": 10, "cost_per_run": 0.5, "fail_share": 0.1, "screens": 20,
           "deny_share": 0.05, "tools": {"crm_update": 14, "research": 6}}


def _enroll(agent_id: str = AGENT, **kw):
    args = {"description": "quoting agent", "owner": "jordan@corp.test",
            "department": "sales", "max_risk": "medium", "max_dollars": 500.0,
            "enrolled_by": "admin@corp.test", "allow_tools": list(_TOOLS)}
    args.update(kw)
    return xa.enroll(agent_id, "agentforce", **args)


def _at(day: int, hour: float = 12) -> float:
    return T0 + day * DAY + hour * 3600


def _seed(days, agent_id: str = AGENT, **overrides) -> None:
    """Put one normal day of totals (with ``overrides``) on each of ``days``,
    exactly as the hooks would have left them, in a single write."""
    shape = {**_NORMAL, **overrides}
    with drift._editing() as agents:
        record = drift._record_for(agents, agent_id, drift._enrolled_ids())
        for day in days:
            bucket = drift._day_bucket(record, _at(day))
            bucket["runs"] += shape["runs"]
            bucket["failures"] += round(shape["runs"] * shape["fail_share"])
            bucket["cost_dollars"] += shape["runs"] * shape["cost_per_run"]
            bucket["tool_calls"] += shape["runs"] * 2
            bucket["screens"] += shape["screens"]
            bucket["denials"] += round(shape["screens"] * shape["deny_share"])
            for tool, times in shape["tools"].items():
                bucket["tools"][tool] = bucket["tools"].get(tool, 0) + times
            record["last_observed_at"] = _at(day)


def _baselined(agent_id: str = AGENT, **enroll_kw) -> None:
    """An enrolled agent with 14 normal days, approved late on the last one."""
    _enroll(agent_id, **enroll_kw)
    _seed(range(14), agent_id)
    drift.approve_baseline(agent_id, actor="dana@corp.test", now=_at(13, 23))


#: The three days after the baseline, and the moment they are judged.
_AFTER = range(15, 18)
_JUDGED = _at(17, 23)


def _kinds(result: dict) -> set[str]:
    return {finding["kind"] for finding in result["findings"]}


def _finding(result: dict, key: str) -> dict:
    return next(f for f in result["findings"] if f["key"] == key)


def _stored() -> dict:
    return json.loads(drift.store_path().read_text(encoding="utf-8"))


def _recorded(agent_id: str = AGENT) -> dict:
    """Everything recorded for the agent, whichever UTC day it landed on (the
    gateway hooks use the real clock, and a test may straddle midnight)."""
    total = drift._empty_totals()
    for day in _stored()["agents"][agent_id]["days"].values():
        drift._add(total, day)
    return total


@pytest.fixture
def audit_rows(monkeypatch):
    """Audit rows written during the test, captured at the documented entry point."""
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

    def alert(event, detail="", *, severity="high"):
        sent.append({"event": event, "detail": detail, "severity": severity})
        return True

    monkeypatch.setattr(ops_alert, "alert", alert)
    return sent


def _of_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["kind"] == kind]


# --------------------------------------------------------------- observation

def test_screen_observations_are_counted_per_utc_day():
    _enroll()
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(0, 23.99))
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(1, 0.01))
    drift.observe_screen(AGENT, "wire_transfer", allowed=False, rule="capability", now=_at(1))
    drift.observe_screen(AGENT, "send_contract", allowed=False, rule="approval_required",
                         now=_at(1))
    days = _stored()["agents"][AGENT]["days"]
    first, second = days[drift._day_key(20_000)], days[drift._day_key(20_001)]
    assert (first["screens"], first["denials"], first["tools"]) == (1, 0, {"crm_update": 1})
    assert (second["screens"], second["denials"], second["approvals_required"]) == (3, 1, 1)
    assert second["tools"] == {"crm_update": 1, "wire_transfer": 1, "send_contract": 1}
    assert _stored()["agents"][AGENT]["last_observed_at"] == _at(1)
    # A late report about an earlier day does not move "last observed" back.
    drift.observe_run(AGENT, now=_at(0))
    assert _stored()["agents"][AGENT]["last_observed_at"] == _at(1)


def test_run_observations_add_up_numbers_tools_and_failures():
    _enroll()
    drift.observe_run(AGENT, cost_dollars=1.25, input_tokens=900, output_tokens=400,
                      tool_calls=6, outcome="success", tools=["crm_update", "research"],
                      now=_at(0))
    drift.observe_run(AGENT, cost_dollars=0.75, input_tokens=100, output_tokens=50,
                      tool_calls=1, outcome="failure", tools=("crm_update",), now=_at(0))
    drift.observe_run(AGENT, now=_at(0))  # an outcome that was not given is not a failure
    day = _stored()["agents"][AGENT]["days"][drift._day_key(20_000)]
    assert (day["runs"], day["failures"], day["tool_calls"]) == (3, 1, 7)
    assert (day["input_tokens"], day["output_tokens"]) == (1000, 450)
    assert day["cost_dollars"] == pytest.approx(2.0)
    assert day["tools"] == {"crm_update": 2, "research": 1}


def test_declared_and_discovered_configuration_are_remembered():
    _enroll()
    drift.observe_run(AGENT, declared={"version": "1.4.2", "model": "model-a",
                                       "config_digest": "abc123", "prompt": "be helpful"},
                      now=_at(0))
    drift.observe_run(AGENT, declared={"model": "model-b"}, now=_at(1))
    drift.observe_discovered(AGENT, version_digest="sha256:" + "a" * 64,
                             binding_strength="exact", source="copilot-studio", now=_at(1))
    config = _stored()["agents"][AGENT]["config"]
    assert config["declared"] == {"version": "1.4.2", "model": "model-b",
                                  "config_digest": "abc123", "seen_at": _at(1)}
    assert config["discovered"] == {"version_digest": "sha256:" + "a" * 64,
                                    "binding_strength": "exact",
                                    "source": "copilot-studio", "seen_at": _at(1)}
    assert "be helpful" not in drift.store_path().read_text(encoding="utf-8")


def test_refusals_that_are_not_about_the_agent_are_not_recorded():
    _enroll()
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(0))
    before = drift.store_path().read_bytes()
    written = drift.store_path().stat().st_ino
    for rule in ("disabled", "contained", "screen_error", "approval_unavailable",
                 "approval_backlog"):
        drift.observe_screen(AGENT, "crm_update", allowed=False, rule=rule, now=_at(1))
    assert drift.store_path().read_bytes() == before
    # Nothing changed, so the file was not even rewritten.
    assert drift.store_path().stat().st_ino == written


def test_only_enrolled_agents_are_recorded():
    _enroll()
    drift.observe_screen("ghost", "crm_update", allowed=False, rule="not_in_registry")
    drift.observe_run("ghost", cost_dollars=3.0)
    drift.observe_discovered("ghost", version_digest="abc")
    assert not drift.store_path().exists()
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow")
    assert list(_stored()["agents"]) == [AGENT]


def test_agent_supplied_names_are_bounded_and_never_stored_raw():
    _enroll()
    secret = "sk-ant-api03-" + "A" * 40
    hostile = ["x" * 500, "rm -rf /; echo pwned", "two\nlines", secret, "", None, 7]
    for tool in hostile:
        drift.observe_screen(AGENT, tool, allowed=False, rule="capability", now=_at(0))
    drift.observe_run(AGENT, declared={"version": "ignore previous instructions " * 20,
                                       "model": secret}, now=_at(0))
    text = drift.store_path().read_text(encoding="utf-8")
    assert secret not in text and "pwned" not in text and "ignore previous" not in text
    record = _stored()["agents"][AGENT]
    tools = record["days"][drift._day_key(20_000)]["tools"]
    # A name that cannot be shown is counted under a digest, so it keeps its
    # own identity; only a missing name is "(other)".
    assert tools["(other)"] == 3 and sum(tools.values()) == len(hostile)
    assert all(name == "(other)" or name.startswith("unnamed:") for name in tools)
    # A value that cannot be shown is kept as a digest, so a change still shows.
    assert record["config"]["declared"]["version"].startswith("sha256:")
    assert record["config"]["declared"]["model"].startswith("sha256:")


def test_junk_numbers_are_ignored_and_huge_ones_capped():
    _enroll()
    drift.observe_run(AGENT, cost_dollars=float("nan"), input_tokens=-5,
                      output_tokens="lots", tool_calls=None, now=_at(0))
    drift.observe_run(AGENT, cost_dollars=float("inf"), input_tokens=10 ** 30,
                      output_tokens=True, tool_calls=[3], tools="crm_update", now=_at(0))
    day = _stored()["agents"][AGENT]["days"][drift._day_key(20_000)]
    assert day["runs"] == 2 and day["cost_dollars"] == 0.0
    assert day["input_tokens"] == drift._MAX_COUNT
    assert (day["output_tokens"], day["tool_calls"], day["tools"]) == (0, 0, {})
    drift.observe_run(AGENT, cost_dollars=1e300, now=_at(0))
    day = _stored()["agents"][AGENT]["days"][drift._day_key(20_000)]
    assert day["cost_dollars"] == float(drift._MAX_COUNT)
    # A whole number too large for a float is capped as well, not an error.
    assert drift._amount(10 ** 400) == float(drift._MAX_COUNT)
    assert drift._amount(-(10 ** 400)) == 0.0


def test_the_record_keeps_only_the_newest_days():
    _enroll()
    for day in range(drift._MAX_DAYS + 6):
        drift.observe_run(AGENT, now=_at(day))
    days = _stored()["agents"][AGENT]["days"]
    assert len(days) == drift._MAX_DAYS
    assert min(days) == drift._day_key(20_006)
    assert max(days) == drift._day_key(20_000 + drift._MAX_DAYS + 5)


def test_distinct_tool_names_are_capped_per_agent():
    _enroll()
    drift.observe_run(AGENT, tools=[f"tool_{n}" for n in range(drift._MAX_TOOLS + 25)],
                      now=_at(0))
    drift.observe_screen(AGENT, "one_more_tool", allowed=True, rule="allow", now=_at(1))
    record = _stored()["agents"][AGENT]
    first = record["days"][drift._day_key(20_000)]["tools"]
    assert len(first) == drift._MAX_TOOLS + 1 and first["(other)"] == 25
    assert record["days"][drift._day_key(20_001)]["tools"] == {"(other)": 1}


def test_one_run_cannot_list_tools_without_limit():
    _enroll()
    drift.observe_run(AGENT, tools=["crm_update"] * 10_000, now=_at(0))
    day = _stored()["agents"][AGENT]["days"][drift._day_key(20_000)]
    assert day["tools"] == {"crm_update": drift._MAX_TOOLS_PER_RUN}


def test_the_number_of_agents_is_capped(monkeypatch):
    monkeypatch.setattr(drift, "_MAX_AGENTS", 2)
    for agent_id in ("bot-a", "bot-b", "bot-c"):
        _enroll(agent_id)
        drift.observe_screen(agent_id, "crm_update", allowed=True, rule="allow")
    assert sorted(_stored()["agents"]) == ["bot-a", "bot-b"]


def test_an_unenrolled_agents_record_makes_way_for_a_new_agent(monkeypatch):
    monkeypatch.setattr(drift, "_MAX_AGENTS", 2)
    for agent_id in ("bot-a", "bot-b"):
        _enroll(agent_id)
        drift.observe_screen(agent_id, "crm_update", allowed=True, rule="allow")
    assert xa.unenroll("bot-a") is True
    _enroll("bot-c")
    drift.observe_screen("bot-c", "crm_update", allowed=True, rule="allow")
    assert sorted(_stored()["agents"]) == ["bot-b", "bot-c"]


def test_concurrent_observations_are_all_counted():
    from concurrent.futures import ThreadPoolExecutor
    _enroll()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda n: drift.observe_screen(
            AGENT, "crm_update", allowed=n % 4 != 0, rule="allow" if n % 4 else "capability",
            now=_at(0)), range(80)))
    day = _stored()["agents"][AGENT]["days"][drift._day_key(20_000)]
    assert (day["screens"], day["denials"], day["tools"]) == (80, 20, {"crm_update": 80})


def test_the_record_is_private_and_holds_only_totals():
    _enroll()
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(0))
    path = drift.store_path()
    assert path.parent == xa.registry_path().parent
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    record = _stored()["agents"][AGENT]
    assert set(record) == {"days", "config", "baseline", "reported", "acknowledged",
                           "last_observed_at", "enrolled_at"}
    assert set(record["days"][drift._day_key(20_000)]) == {
        "runs", "failures", "tool_calls", "input_tokens", "output_tokens", "screens",
        "denials", "approvals_required", "cost_dollars", "tools"}


# ---------------------------------------------------------- hooks never raise

@pytest.mark.parametrize("call", [
    lambda: drift.observe_screen(None, None, allowed=None, rule=None),
    lambda: drift.observe_screen(["a"], {"b": 1}, allowed="yes", rule=["x"]),
    lambda: drift.observe_screen(AGENT, "crm_update", allowed=True, now="soon"),
    lambda: drift.observe_run(AGENT, cost_dollars=object(), tools=object(), declared=[1, 2]),
    lambda: drift.observe_run(AGENT, declared={"version": object()}, now=float("nan")),
    lambda: drift.observe_run(AGENT, now=1e30),
    lambda: drift.observe_discovered(AGENT, version_digest=None, source=object()),
    lambda: drift.observe_discovered(object(), version_digest="abc"),
])
def test_hooks_never_raise_on_junk_input(call):
    _enroll()
    assert call() is None


@pytest.mark.parametrize("broken", ["_load_store", "_enrolled_ids", "settings", "_dump"])
def test_hooks_never_raise_when_the_module_itself_fails(monkeypatch, broken):
    _enroll()

    def boom(*_a, **_kw):
        raise RuntimeError("drift internals unavailable")

    monkeypatch.setattr(drift, broken, boom)
    assert drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow") is None
    assert drift.observe_run(AGENT, cost_dollars=1.0) is None
    assert drift.observe_discovered(AGENT, version_digest="abc") is None
    assert not drift.store_path().exists()


def test_hooks_record_nothing_when_enrollment_cannot_be_read():
    _enroll()
    xa.registry_path().write_text("{ not json", encoding="utf-8")
    assert drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow") is None
    assert not drift.store_path().exists()


# ---------------------------------------------------- malformed file handling

_BROKEN_STORES = [
    "{ not json",
    "[]",
    '{"version": 1}',
    '{"version": 99, "agents": {}}',
    '{"version": 1, "agents": []}',
    '{"version": 1, "agents": {"sf-quotebot": 7}}',
    '{"version": 1, "agents": {"sf-quotebot": {"days": []}}}',
    '{"version": 1, "agents": {"sf-quotebot": {"days": {"2024-01-01": 3}}}}',
    '{"version": 1, "agents": {"sf-quotebot": {"days": {}, "baseline": "yes"}}}',
    '{"version": 1, "agents": {"sf-quotebot": {"days": {}, "reported": [1]}}}',
]


@pytest.mark.parametrize("payload", _BROKEN_STORES)
def test_a_record_that_cannot_be_read_is_never_overwritten(payload):
    _enroll()
    path = drift.store_path()
    path.write_text(payload, encoding="utf-8")
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow")
    drift.observe_run(AGENT, cost_dollars=1.0)
    drift.observe_discovered(AGENT, version_digest="abc")
    assert path.read_text(encoding="utf-8") == payload
    for refused in (
        lambda: drift.evaluate(AGENT),
        lambda: drift.baseline(AGENT),
        lambda: drift.approve_baseline(AGENT, actor="dana@corp.test", force=True),
        lambda: drift.acknowledge(AGENT, "volume:up", actor="dana@corp.test"),
        lambda: drift.check(AGENT),
        drift.check_all,
        drift.roster_view,
        lambda: drift.detail(AGENT),
    ):
        with pytest.raises(drift.AgentDriftStoreError, match="cannot be read"):
            refused()
    assert path.read_text(encoding="utf-8") == payload


def test_junk_inside_a_readable_record_reads_as_zero_not_as_an_error():
    _enroll()
    drift.store_path().write_text(json.dumps({"version": 1, "agents": {AGENT: {
        "days": {drift._day_key(20_000): {"runs": "many", "cost_dollars": None,
                                          "screens": -4, "tools": {"crm_update": "x"}}},
        "config": {"declared": 5}, "baseline": None, "reported": {"volume:up": 3},
        "acknowledged": {"volume:up": "yes"}}}}), encoding="utf-8")
    result = drift.evaluate(AGENT, now=_at(0))
    assert result["state"] == "no_baseline" and result["current"]["runs"] == 0
    drift.observe_run(AGENT, cost_dollars=1.0, now=_at(0))
    day = _stored()["agents"][AGENT]["days"][drift._day_key(20_000)]
    assert (day["runs"], day["cost_dollars"], day["screens"], day["tools"]) == (1, 1.0, 0, {})


# ------------------------------------------------------------------- disabled

def test_disabled_hooks_and_checks_do_nothing(monkeypatch, audit_rows, alerts):
    _baselined()
    _seed(_AFTER, runs=70, tools={"wire_transfer": 20})
    before = drift.store_path().read_bytes()
    monkeypatch.setenv("MAVERICK_AGENT_DRIFT", "0")
    audit_rows.clear()
    drift.observe_screen(AGENT, "wire_transfer", allowed=True, rule="allow", now=_JUDGED)
    drift.observe_run(AGENT, cost_dollars=9.0, now=_JUDGED)
    drift.observe_discovered(AGENT, version_digest="abc", now=_JUDGED)
    assert drift.store_path().read_bytes() == before
    result = drift.check(AGENT, now=_JUDGED)
    assert result["enabled"] is False and result["new_findings"] == []
    assert result["findings"] == [] and result["contained"] is False
    # Blind is not the same as clean: never "within_baseline" while it is off.
    assert result["state"] == "learning" and "turned off" in result["reason"]
    assert drift.check_all(now=_JUDGED) == []
    assert audit_rows == [] and alerts == []
    assert xa.containment_state(AGENT) is False
    with pytest.raises(drift.AgentDriftError, match="turned off"):
        drift.approve_baseline(AGENT, actor="dana@corp.test", now=_JUDGED)


def test_disabled_from_the_start_writes_no_file(monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_DRIFT", "0")
    _enroll()
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow")
    xa.screen(AGENT, "crm_update", risk="low")
    path = drift.store_path()
    assert not path.exists() and not path.with_name(path.name + ".lock").exists()
    assert drift.evaluate(AGENT)["state"] == "no_baseline"
    assert drift.evaluate(AGENT)["ready_to_approve"] is False


# ------------------------------------------------------------------- baseline

def test_no_baseline_until_one_is_approved():
    assert drift.evaluate("ghost")["state"] == "no_baseline"
    _enroll()
    empty = drift.evaluate(AGENT, now=_at(0))
    assert empty["state"] == "no_baseline" and empty["findings"] == []
    assert empty["baseline"] is None and empty["ready_to_approve"] is False
    assert "0 runs and 0 screened actions" in empty["reason"]
    assert drift.baseline(AGENT) is None
    _seed(range(3))
    ready = drift.evaluate(AGENT, now=_at(2, 23))
    assert ready["state"] == "no_baseline" and ready["ready_to_approve"] is True
    assert ready["current"]["runs"] == 30


def test_approval_is_refused_with_too_little_data_and_says_why():
    _enroll()
    drift.observe_run(AGENT, now=_at(0))
    drift.observe_run(AGENT, now=_at(0))
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(0))
    with pytest.raises(drift.AgentDriftError) as refused:
        drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(0, 13))
    message = str(refused.value)
    assert "not enough activity" in message
    assert "2 runs and 1 screened action in the last 14 days" in message
    assert "at least 5 runs or 10 screened actions are needed" in message
    assert "force" in message
    assert drift.baseline(AGENT) is None


def test_force_approves_a_thin_baseline_and_says_so(audit_rows):
    _enroll()
    drift.observe_run(AGENT, now=_at(0))
    approved = drift.approve_baseline(AGENT, actor="dana@corp.test", force=True,
                                      now=_at(0, 13))
    assert approved["forced"] is True and approved["runs"] == 1
    assert _of_kind(audit_rows, "agent_baseline_approved")[0]["forced"] is True


def test_approval_records_who_when_and_what(audit_rows):
    _enroll()
    drift.observe_discovered(AGENT, version_digest="digest-1", source="bedrock", now=_at(0))
    _seed(range(14))
    approved = drift.approve_baseline(AGENT, actor="  dana@corp.test ", now=_at(13, 23))
    assert approved == drift.baseline(AGENT)
    assert approved["approved_by"] == "dana@corp.test"
    assert approved["approved_at"] == _at(13, 23)
    assert (approved["window_days"], approved["forced"]) == (14, False)
    assert (approved["from_day"], approved["to_day"]) == (
        drift._day_key(20_000), drift._day_key(20_013))
    assert (approved["runs"], approved["screens"], approved["denials"]) == (140, 280, 14)
    assert approved["tools"] == {"crm_update": 196, "research": 84}
    assert approved["runs_per_day"] == pytest.approx(10.0, abs=0.05)
    assert approved["cost_per_run"] == pytest.approx(0.5)
    assert approved["denial_rate"] == pytest.approx(0.05)
    assert approved["config"]["discovered"]["version_digest"] == "digest-1"
    row, = _of_kind(audit_rows, "agent_baseline_approved")
    assert row["agent"] == "agent_drift" and row["external_agent"] == AGENT
    assert row["approved_by"] == "dana@corp.test"
    assert (row["window_days"], row["runs"], row["screens"], row["tools"]) == (14, 140, 280, 2)
    assert (row["forced"], row["replaced"]) == (False, False)


def test_a_shorter_baseline_window_can_be_chosen():
    _enroll()
    _seed(range(14))
    _seed([13], runs=30)
    approved = drift.approve_baseline(AGENT, actor="dana@corp.test", window_days=1,
                                      now=_at(13, 23))
    assert (approved["window_days"], approved["runs"]) == (1, 40)
    assert approved["from_day"] == approved["to_day"] == drift._day_key(20_013)


@pytest.mark.parametrize("window_days", [0, -1, 31, 2.5, "7", True])
def test_approval_rejects_a_bad_window(window_days):
    _enroll()
    _seed(range(14))
    with pytest.raises(drift.AgentDriftError, match="whole number from 1 to 30"):
        drift.approve_baseline(AGENT, actor="dana@corp.test", window_days=window_days,
                               now=_at(13, 23))


@pytest.mark.parametrize("actor", ["", "   ", None, 7])
def test_approval_needs_a_named_approver(actor):
    _enroll()
    _seed(range(14))
    with pytest.raises(drift.AgentDriftError, match="who is making this decision"):
        drift.approve_baseline(AGENT, actor=actor, now=_at(13, 23))
    assert drift.baseline(AGENT) is None


def test_approval_is_refused_for_an_agent_that_is_not_enrolled():
    with pytest.raises(drift.AgentDriftError, match="not an enrolled agent"):
        drift.approve_baseline("ghost", actor="dana@corp.test", force=True)
    assert not drift.store_path().exists()


def test_an_audit_refusal_stops_the_approval(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit.errors import AuditRefused
    _enroll()
    _seed(range(14))

    def refuse(*_a, **_kw):
        raise AuditRefused("signing key unavailable")

    monkeypatch.setattr(audit_pkg, "record", refuse)
    with pytest.raises(AuditRefused):
        drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    assert _stored()["agents"][AGENT]["baseline"] is None


def test_string_audit_kinds_reach_the_real_audit_log():
    from maverick.paths import data_dir
    _baselined()
    rows = [json.loads(line) for path in data_dir("audit").glob("*.ndjson")
            for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    approved = [row for row in rows if row["kind"] == "agent_baseline_approved"]
    assert len(approved) == 1 and approved[0]["approved_by"] == "dana@corp.test"


# ----------------------------------------------------------------- evaluation

def test_activity_like_the_baseline_is_within_baseline():
    _baselined()
    _seed(_AFTER)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert result["state"] == "within_baseline" and result["findings"] == []
    assert result["findings_count"] == 0 and result["highest_severity"] == ""
    assert result["compared"] == ["tool_mix", "volume", "cost", "denial_rate", "failure_rate"]
    assert result["skipped"] == []
    assert result["current"]["runs"] == 30 and result["baseline"]["runs"] == 140
    assert "matches the approved baseline" in result["reason"]


def test_the_day_of_approval_is_within_baseline():
    _baselined()
    result = drift.evaluate(AGENT, now=_at(13, 23.5))
    assert result["state"] == "within_baseline"
    # The window never reaches back before the approval day.
    assert result["current"]["runs"] == 10


def test_a_thin_baseline_leaves_the_agent_in_learning():
    _enroll()
    drift.observe_run(AGENT, now=_at(0))
    drift.observe_screen(AGENT, "crm_update", allowed=True, rule="allow", now=_at(0))
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=_at(0, 13))
    drift.observe_run(AGENT, now=_at(1))
    result = drift.evaluate(AGENT, now=_at(1, 13))
    assert result["state"] == "learning" and result["findings"] == []
    assert result["compared"] == []
    assert result["skipped"] == ["tool_mix", "volume", "cost", "denial_rate", "failure_rate"]
    assert result["reason"] == (
        "There is not enough activity to compare with the approved baseline yet: "
        "2 runs and 1 screened action recently, against 1 run and 1 screened action "
        "in the baseline.")


def test_new_tool_is_a_high_severity_finding():
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert result["state"] == "drifted" and _kinds(result) == {"new_tool"}
    finding = _finding(result, "new_tool:wire_transfer")
    assert finding["severity"] == "high" and finding["tool"] == "wire_transfer"
    assert (finding["baseline"], finding["current"]) == (0, 3)
    assert "wire_transfer" in finding["summary"] and "3 times" in finding["summary"]
    assert result["highest_severity"] == "high" and result["findings_count"] == 1


def test_a_refused_attempt_at_an_unknown_tool_still_counts_as_new():
    _baselined()
    drift.observe_screen(AGENT, "delete_records", allowed=False, rule="capability",
                         now=_at(15))
    result = drift.evaluate(AGENT, now=_at(15, 13))
    assert "new_tool:delete_records" in {f["key"] for f in result["findings"]}


def test_tools_beyond_the_cap_are_reported_as_one_finding():
    _baselined()
    with drift._editing() as agents:
        drift._day_bucket(agents[AGENT], _at(15))["tools"]["(other)"] = 4
    finding = _finding(drift.evaluate(AGENT, now=_at(15, 13)), "new_tool:(other)")
    assert finding["severity"] == "high" and "not tracked by name" in finding["summary"]


@pytest.mark.parametrize("tools, severity", [
    ({"crm_update": 2, "research": 18}, "low"),
    ({"research": 20}, "medium"),
])
def test_tool_mix_shift(tools, severity):
    _baselined()
    _seed(_AFTER, tools=tools)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert _kinds(result) == {"tool_mix"}
    finding = _finding(result, "tool_mix")
    assert finding["severity"] == severity
    assert finding["score"] >= finding["threshold"] == 0.15
    assert finding["baseline"] == {"crm_update": 0.7, "research": 0.3}
    assert finding["current"]["research"] >= 0.9
    assert "mix of tools" in finding["summary"]


def test_tool_mix_needs_a_minimum_sample():
    _baselined()
    _seed([17], screens=0, tools={"research": 19})
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert "tool_mix" in result["skipped"] and "tool_mix" not in _kinds(result)


@pytest.mark.parametrize("runs, key, severity", [
    (40, "volume:up", "medium"),
    (70, "volume:up", "high"),
    (1, "volume:down", "low"),
])
def test_volume_change(runs, key, severity):
    _baselined()
    _seed(_AFTER, runs=runs)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert "volume" in _kinds(result)
    finding = _finding(result, key)
    assert finding["severity"] == severity
    assert finding["baseline"] == pytest.approx(10.0, abs=0.1)
    assert finding["current"] == float(runs)
    assert finding["threshold"] == 3.0
    assert f"{runs:.1f} runs a day" in finding["summary"]


def test_an_agent_that_goes_quiet_is_a_low_volume_finding():
    _baselined()
    result = drift.evaluate(AGENT, now=_at(20, 23))
    assert result["state"] == "drifted" and _kinds(result) == {"volume", "silent"}
    finding = _finding(result, "volume:down")
    assert finding["severity"] == "low" and finding["current"] == 0.0
    assert "far less often" in finding["summary"]


def test_a_morning_batch_is_not_a_volume_spike():
    _baselined()
    _seed([14, 15, 16])
    _seed([17])  # the whole day's usual work, done by 06:00
    result = drift.evaluate(AGENT, now=_at(17, 6))
    assert "volume" in result["compared"] and "volume" not in _kinds(result)
    assert result["current"]["runs_per_day"] == 10.0


def test_a_quiet_morning_is_not_a_volume_drop():
    _baselined()
    _seed([14, 15, 16])
    for moment in (_at(14, 0.1), _at(17, 0.1), _at(17, 11)):
        result = drift.evaluate(AGENT, now=moment)
        assert "volume" in result["compared"] and "volume" not in _kinds(result)


def test_nothing_yet_since_approval_is_learning_not_a_drop():
    _enroll()
    _seed(range(13))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 0.5))
    result = drift.evaluate(AGENT, now=_at(13, 1))
    assert result["state"] == "learning" and result["compared"] == []
    assert result["current"]["runs"] == 0


def test_a_spike_is_caught_the_day_it_happens_and_stays_visible_overnight():
    _baselined()
    _seed([15, 16])
    _seed([17], runs=100)
    finding = _finding(drift.evaluate(AGENT, now=_at(17, 6)), "volume:up")
    assert (finding["severity"], finding["current"]) == ("medium", 40.0)
    # Just after midnight the new day is empty; the whole days still show it.
    finding = _finding(drift.evaluate(AGENT, now=_at(18, 0.1)), "volume:up")
    assert (finding["severity"], finding["current"]) == ("medium", 55.0)


def test_a_baseline_approved_minutes_after_first_activity_has_a_sane_rate():
    _enroll()
    with drift._editing() as agents:
        record = drift._record_for(agents, AGENT, drift._enrolled_ids())
        drift._day_bucket(record, _at(0, 0.05))["runs"] = 6
    approved = drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(0, 0.1))
    # Worked out over one whole day at least, not over six minutes.
    assert approved["runs_per_day"] == pytest.approx(6.0)


@pytest.mark.parametrize("cost_per_run, key, severity", [
    (1.25, "cost:up", "medium"),
    (2.5, "cost:up", "high"),
    (0.1, "cost:down", "low"),
])
def test_cost_per_run_change(cost_per_run, key, severity):
    _baselined()
    _seed(_AFTER, cost_per_run=cost_per_run)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert _kinds(result) == {"cost"}
    finding = _finding(result, key)
    assert finding["severity"] == severity
    assert (finding["baseline"], finding["current"]) == (0.5, cost_per_run)
    assert f"${cost_per_run:,.2f} a run" in finding["summary"]


def test_cost_needs_enough_runs_on_both_sides():
    _baselined()
    _seed([17], runs=4, cost_per_run=50.0)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert "cost" in result["skipped"] and "cost" not in _kinds(result)


@pytest.mark.parametrize("deny_share, severity", [(0.25, "medium"), (0.5, "high")])
def test_denial_rate_rise(deny_share, severity):
    _baselined()
    _seed(_AFTER, deny_share=deny_share)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert _kinds(result) == {"denial_rate"}
    finding = _finding(result, "denial_rate")
    assert finding["severity"] == severity
    assert (finding["baseline"], finding["current"]) == (0.05, deny_share)
    assert f"{deny_share:.0%} now, 5% in its approved baseline" in finding["summary"]


def test_a_falling_denial_rate_is_not_a_finding():
    _enroll()
    _seed(range(14), deny_share=0.5)
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    _seed(_AFTER, deny_share=0.0)
    assert drift.evaluate(AGENT, now=_JUDGED)["state"] == "within_baseline"


@pytest.mark.parametrize("fail_share, severity", [(0.4, "low"), (0.6, "medium")])
def test_failure_rate_rise(fail_share, severity):
    _baselined()
    _seed(_AFTER, fail_share=fail_share)
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert _kinds(result) == {"failure_rate"}
    finding = _finding(result, "failure_rate")
    assert finding["severity"] == severity
    assert (finding["baseline"], finding["current"]) == (0.1, fail_share)
    assert "runs are failing" in finding["summary"]


def test_thresholds_come_from_settings(tmp_path):
    _baselined()
    _seed(_AFTER, runs=40)
    assert _kinds(drift.evaluate(AGENT, now=_JUDGED)) == {"volume"}
    _configure(tmp_path, "[agent_drift]\nvolume_ratio = 5.0\n")
    assert drift.evaluate(AGENT, now=_JUDGED)["state"] == "within_baseline"
    _configure(tmp_path, "[agent_drift]\nvolume_ratio = 1.5\n")
    assert _finding(drift.evaluate(AGENT, now=_JUDGED), "volume:up")["severity"] == "high"


def test_a_discovered_configuration_change_is_high_severity():
    _enroll()
    drift.observe_discovered(AGENT, version_digest="digest-1", binding_strength="exact",
                             source="copilot-studio", now=_at(0))
    _seed(range(14))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    _seed(_AFTER)
    assert drift.evaluate(AGENT, now=_JUDGED)["state"] == "within_baseline"
    drift.observe_discovered(AGENT, version_digest="digest-2", source="copilot-studio",
                             now=_at(17))
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert result["state"] == "drifted" and _kinds(result) == {"config_changed"}
    finding, = result["findings"]
    assert (finding["severity"], finding["source"]) == ("high", "discovery")
    assert (finding["baseline"], finding["current"]) == ("digest-1", "digest-2")
    assert finding["key"].startswith("config_changed:discovery:")
    assert "home platform" in finding["summary"]


def test_self_reported_changes_are_medium_severity():
    _enroll()
    drift.observe_run(AGENT, declared={"version": "1.4.2", "model": "model-a",
                                       "config_digest": "cfg-1"}, now=_at(0))
    _seed(range(14))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    _seed(_AFTER)
    drift.observe_run(AGENT, cost_dollars=0.5, declared={
        "version": "1.5.0", "model": "model-b", "config_digest": "cfg-2"}, now=_at(17))
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert _kinds(result) == {"config_changed", "model_changed", "version_changed"}
    assert {f["severity"] for f in result["findings"]} == {"medium"}
    assert {f["source"] for f in result["findings"]} == {"self_reported"}
    changed = {f["kind"]: (f["baseline"], f["current"]) for f in result["findings"]}
    assert changed == {"config_changed": ("cfg-1", "cfg-2"),
                       "model_changed": ("model-a", "model-b"),
                       "version_changed": ("1.4.2", "1.5.0")}
    assert result["highest_severity"] == "medium"


def test_a_fingerprint_the_baseline_never_had_cannot_be_compared():
    _baselined()
    _seed(_AFTER)
    drift.observe_discovered(AGENT, version_digest="digest-9", now=_at(17))
    drift.observe_run(AGENT, cost_dollars=0.5, declared={"model": "model-z"}, now=_at(17))
    assert drift.evaluate(AGENT, now=_JUDGED)["state"] == "within_baseline"


def test_findings_are_listed_most_severe_first():
    _baselined()
    _seed(_AFTER, runs=40, fail_share=0.4,
          tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    result = drift.evaluate(AGENT, now=_JUDGED)
    assert [f["severity"] for f in result["findings"]] == ["high", "medium", "low"]
    assert [f["kind"] for f in result["findings"]] == ["new_tool", "volume", "failure_rate"]
    assert result["findings_count"] == 3 and "3 findings need review" in result["reason"]
    json.dumps(result)  # the whole result is plain data


def test_evaluate_changes_nothing():
    _baselined()
    _seed(_AFTER, runs=70)
    before = drift.store_path().read_bytes()
    drift.evaluate(AGENT, now=_JUDGED)
    drift.roster_view(now=_JUDGED)
    drift.detail(AGENT, now=_JUDGED)
    assert drift.store_path().read_bytes() == before


# ------------------------------------------------------------------- reaction

def test_check_audits_and_alerts_new_findings_once(audit_rows, alerts):
    _baselined()
    _seed(_AFTER, runs=40, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    audit_rows.clear()
    first = drift.check(AGENT, now=_JUDGED)
    assert first["state"] == "drifted" and first["reaction"] == "alert"
    assert first["new_findings"] == ["new_tool:wire_transfer", "volume:up"]
    assert first["contained"] is False
    rows = _of_kind(audit_rows, "agent_drift_detected")
    assert [(r["finding"], r["finding_kind"], r["severity"]) for r in rows] == [
        ("new_tool:wire_transfer", "new_tool", "high"), ("volume:up", "volume", "medium")]
    assert all(r["agent"] == "agent_drift" and r["external_agent"] == AGENT for r in rows)
    assert (rows[0]["baseline"], rows[0]["current"]) == (0, 3)
    assert (rows[0]["reaction"], rows[0]["contained"]) == ("alert", False)
    alert, = alerts
    assert (alert["event"], alert["severity"]) == ("agent_drift.detected", "high")
    assert alert["detail"].startswith(f"{AGENT} has moved away from its approved baseline.")
    assert "wire_transfer" in alert["detail"] and "1 more finding needs review" in alert["detail"]

    for later in (_JUDGED + 60, _JUDGED + 3 * 3600):
        again = drift.check(AGENT, now=later)
        assert again["state"] == "drifted" and again["new_findings"] == []
    assert len(_of_kind(audit_rows, "agent_drift_detected")) == 2 and len(alerts) == 1
    assert _finding(again, "volume:up")["reported_at"] == _JUDGED


@pytest.mark.parametrize("severity, expected", [("medium", "warning"), ("low", "info")])
def test_alert_severity_follows_the_worst_new_finding(alerts, severity, expected):
    _baselined()
    _seed(_AFTER, **({"runs": 40} if severity == "medium" else {"fail_share": 0.4}))
    drift.check(AGENT, now=_JUDGED)
    assert [a["severity"] for a in alerts] == [expected]


def test_check_without_findings_does_nothing(audit_rows, alerts):
    _baselined()
    _seed(_AFTER)
    audit_rows.clear()
    before = drift.store_path().read_bytes()
    result = drift.check(AGENT, now=_JUDGED)
    assert result["state"] == "within_baseline" and result["new_findings"] == []
    assert audit_rows == [] and alerts == []
    assert drift.store_path().read_bytes() == before
    with pytest.raises(drift.AgentDriftError):
        drift.check("ghost")


def test_a_finding_that_gets_worse_is_reported_again(audit_rows, alerts):
    _baselined()
    _seed(_AFTER, runs=40)
    assert drift.check(AGENT, now=_JUDGED)["new_findings"] == ["volume:up"]
    _seed([17], runs=120)
    worse = drift.check(AGENT, now=_JUDGED + 60)
    assert worse["new_findings"] == ["volume:up"]
    assert [a["severity"] for a in alerts] == ["warning", "high"]
    assert [r["severity"] for r in _of_kind(audit_rows, "agent_drift_detected")] == [
        "medium", "high"]
    assert drift.check(AGENT, now=_JUDGED + 120)["new_findings"] == []


def test_a_finding_that_goes_away_and_comes_back_is_reported_again(alerts):
    _baselined()
    _seed([15], runs=40)
    _seed([16, 17], runs=40)
    assert drift.check(AGENT, now=_JUDGED)["new_findings"] == ["volume:up"]
    # Back to normal for a week: the old finding is forgotten after a quiet day.
    _seed(range(18, 25))
    calm = drift.check(AGENT, now=_at(24, 23))
    assert calm["state"] == "within_baseline" and calm["new_findings"] == []
    assert _stored()["agents"][AGENT]["reported"] == {}
    _seed(range(25, 28), runs=40)
    assert drift.check(AGENT, now=_at(27, 23))["new_findings"] == ["volume:up"]
    assert len(alerts) == 2


def test_a_brief_gap_does_not_cause_a_second_report(tmp_path, alerts):
    _baselined()
    _seed(_AFTER, runs=40)
    assert drift.check(AGENT, now=_JUDGED)["new_findings"] == ["volume:up"]
    # The finding drops out for a few minutes (here: a looser limit), then returns.
    _configure(tmp_path, "[agent_drift]\nvolume_ratio = 5.0\n")
    assert drift.check(AGENT, now=_JUDGED + 600)["state"] == "within_baseline"
    _configure(tmp_path, "")
    back = drift.check(AGENT, now=_JUDGED + 1200)
    assert back["state"] == "drifted" and back["new_findings"] == []
    assert len(alerts) == 1


def test_what_was_reported_is_bounded():
    entries = {f"new_tool:t{n}": {"at": n, "seen": n, "severity": "high"}
               for n in range(drift._MAX_REPORTED + 40)}
    kept = drift._remember(entries, [], 50.0, hold=set(), pending=False)
    assert len(kept) == drift._MAX_REPORTED
    assert f"new_tool:t{drift._MAX_REPORTED + 39}" in kept and "new_tool:t0" not in kept


def test_default_reaction_never_contains(audit_rows, alerts):
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    result = drift.check(AGENT, now=_JUDGED)
    assert result["highest_severity"] == "high" and result["contained"] is False
    assert xa.containment_state(AGENT) is False
    assert _of_kind(audit_rows, "external_agent_contained") == []
    assert "contained" not in alerts[0]["detail"]


def test_contain_reaction_contains_on_a_high_finding(tmp_path, audit_rows, alerts):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    result = drift.check(AGENT, now=_JUDGED)
    assert result["reaction"] == "contain" and result["contained"] is True
    assert xa.containment_state(AGENT) is True
    contained, = _of_kind(audit_rows, "external_agent_contained")
    assert contained["contained_by"] == "drift" and contained["external_agent"] == AGENT
    detected, = _of_kind(audit_rows, "agent_drift_detected")
    assert (detected["reaction"], detected["contained"]) == ("contain", True)
    assert "has been contained until someone reviews it" in alerts[0]["detail"]
    # The gateway now refuses the agent.
    assert xa.screen(AGENT, "crm_update", risk="low")["rule"] == "contained"


def test_contain_reaction_leaves_lower_severities_alone(tmp_path, audit_rows, alerts):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, runs=40, fail_share=0.4)
    result = drift.check(AGENT, now=_JUDGED)
    assert result["new_findings"] == ["volume:up", "failure_rate"]
    assert result["highest_severity"] == "medium" and result["contained"] is False
    assert xa.containment_state(AGENT) is False
    assert _of_kind(audit_rows, "external_agent_contained") == [] and len(alerts) == 1


def test_a_released_agent_is_not_contained_again_for_the_same_finding(tmp_path, audit_rows):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    assert drift.check(AGENT, now=_JUDGED)["contained"] is True
    assert xa.release(AGENT, released_by="dana@corp.test") is True
    again = drift.check(AGENT, now=_JUDGED + 60)
    assert again["state"] == "drifted" and again["contained"] is False
    assert xa.containment_state(AGENT) is False
    assert len(_of_kind(audit_rows, "external_agent_contained")) == 1


def test_an_agent_that_is_already_contained_is_left_as_it_is(tmp_path, audit_rows):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    assert xa.contain(AGENT, contained_by="soc") is True
    result = drift.check(AGENT, now=_JUDGED)
    assert result["new_findings"] == ["new_tool:wire_transfer"]
    assert result["contained"] is False and "containment_failed" not in result
    assert [r["contained_by"] for r in _of_kind(audit_rows, "external_agent_contained")] == [
        "soc"]


def test_a_failed_containment_is_reported_and_tried_again(tmp_path, monkeypatch, alerts):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, runs=40, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    real_contain = xa.contain

    def unavailable(*_a, **_kw):
        raise xa.ExternalAgentsDependencyError("enrollment authority is unavailable")

    monkeypatch.setattr(xa, "contain", unavailable)
    failed = drift.check(AGENT, now=_JUDGED)
    assert failed["contained"] is False and failed["containment_failed"] is True
    assert failed["new_findings"] == ["new_tool:wire_transfer", "volume:up"]
    assert "could not be contained automatically" in alerts[0]["detail"]

    monkeypatch.setattr(xa, "contain", real_contain)
    retried = drift.check(AGENT, now=_JUDGED + 60)
    # Containment is tried again without reporting the finding a second time.
    assert retried["new_findings"] == []
    assert retried["contained"] is True and xa.containment_state(AGENT) is True
    assert "has been contained" in alerts[1]["detail"]
    assert drift.check(AGENT, now=_JUDGED + 120)["new_findings"] == []
    assert len(alerts) == 2


def test_containment_happens_before_the_finding_is_marked_reported(
        tmp_path, monkeypatch, alerts):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    real_report = drift._report_new

    def interrupted(*_a, **_kw):
        raise RuntimeError("stopped before the finding was remembered")

    monkeypatch.setattr(drift, "_report_new", interrupted)
    with pytest.raises(RuntimeError):
        drift.check(AGENT, now=_JUDGED)
    # The agent is already contained, and nothing claims the finding was handled.
    assert xa.containment_state(AGENT) is True
    assert _stored()["agents"][AGENT]["reported"] == {} and alerts == []
    monkeypatch.setattr(drift, "_report_new", real_report)
    resumed = drift.check(AGENT, now=_JUDGED + 60)
    assert resumed["new_findings"] == ["new_tool:wire_transfer"] and len(alerts) == 1


def test_checks_running_at_once_report_a_finding_once(audit_rows, alerts):
    from concurrent.futures import ThreadPoolExecutor
    _baselined()
    _seed(_AFTER, runs=40, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    audit_rows.clear()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: drift.check(AGENT, now=_JUDGED), range(8)))
    reported = [key for result in results for key in result["new_findings"]]
    assert sorted(reported) == ["new_tool:wire_transfer", "volume:up"]
    assert len(_of_kind(audit_rows, "agent_drift_detected")) == 2 and len(alerts) == 1


def test_an_audit_refusal_leaves_the_finding_unreported(monkeypatch, alerts):
    import maverick.audit as audit_pkg
    from maverick.audit.errors import AuditRefused
    _baselined()
    _seed(_AFTER, runs=40)
    real_record = audit_pkg.record

    def refuse(*_a, **_kw):
        raise AuditRefused("signing key unavailable")

    monkeypatch.setattr(audit_pkg, "record", refuse)
    with pytest.raises(AuditRefused):
        drift.check(AGENT, now=_JUDGED)
    with pytest.raises(AuditRefused):
        drift.check_all(now=_JUDGED)
    assert alerts == [] and _stored()["agents"][AGENT]["reported"] == {}
    monkeypatch.setattr(audit_pkg, "record", real_record)
    assert drift.check(AGENT, now=_JUDGED + 60)["new_findings"] == ["volume:up"]
    assert len(alerts) == 1


# ---------------------------------------------------------------- acknowledge

def test_acknowledging_a_finding_dismisses_it(audit_rows, alerts):
    _baselined()
    _seed(_AFTER, runs=40)
    assert drift.check(AGENT, now=_JUDGED)["state"] == "drifted"
    audit_rows.clear()
    out = drift.acknowledge(AGENT, "volume:up", actor="dana@corp.test", now=_JUDGED + 60)
    assert out == {"agent_id": AGENT, "finding": "volume:up",
                   "acknowledged_by": "dana@corp.test", "acknowledged_at": _JUDGED + 60}
    row, = _of_kind(audit_rows, "agent_drift_acknowledged")
    assert (row["external_agent"], row["finding"], row["finding_kind"]) == (
        AGENT, "volume:up", "volume")
    assert (row["severity"], row["acknowledged_by"]) == ("medium", "dana@corp.test")

    result = drift.check(AGENT, now=_JUDGED + 120)
    assert result["state"] == "within_baseline" and result["findings_count"] == 0
    finding = _finding(result, "volume:up")
    assert finding["acknowledged"] is True
    assert (finding["acknowledged_by"], finding["acknowledged_at"]) == (
        "dana@corp.test", _JUDGED + 60)
    assert result["new_findings"] == [] and len(alerts) == 1
    assert drift.roster_view(now=_JUDGED + 120)[0]["findings_count"] == 0


def test_only_an_open_finding_can_be_acknowledged():
    _baselined()
    _seed(_AFTER, runs=40)
    for key in ("new_tool:wire_transfer", "volume:down", "", None):
        with pytest.raises(drift.AgentDriftError, match="no open finding"):
            drift.acknowledge(AGENT, key, actor="dana@corp.test", now=_JUDGED)
    with pytest.raises(drift.AgentDriftError, match="no open finding"):
        drift.acknowledge("ghost", "volume:up", actor="dana@corp.test", now=_JUDGED)
    with pytest.raises(drift.AgentDriftError, match="who is making this decision"):
        drift.acknowledge(AGENT, "volume:up", actor="", now=_JUDGED)
    drift.acknowledge(AGENT, "volume:up", actor="dana@corp.test", now=_JUDGED)
    with pytest.raises(drift.AgentDriftError, match="no open finding"):
        drift.acknowledge(AGENT, "volume:up", actor="dana@corp.test", now=_JUDGED)


def test_an_acknowledged_finding_that_gets_worse_is_open_again(alerts):
    _baselined()
    _seed(_AFTER, runs=40)
    drift.check(AGENT, now=_JUDGED)
    drift.acknowledge(AGENT, "volume:up", actor="dana@corp.test", now=_JUDGED)
    _seed([17], runs=120)
    result = drift.check(AGENT, now=_JUDGED + 60)
    assert result["state"] == "drifted" and result["highest_severity"] == "high"
    assert _finding(result, "volume:up")["acknowledged"] is False
    assert result["new_findings"] == ["volume:up"] and len(alerts) == 2


def test_a_new_baseline_clears_findings_and_acknowledgements(audit_rows):
    _baselined()
    _seed(_AFTER, runs=40, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    drift.check(AGENT, now=_JUDGED)
    drift.acknowledge(AGENT, "volume:up", actor="dana@corp.test", now=_JUDGED)
    approved = drift.approve_baseline(AGENT, actor="sam@corp.test", window_days=3,
                                      now=_JUDGED + 60)
    assert approved["approved_by"] == "sam@corp.test" and "wire_transfer" in approved["tools"]
    assert _of_kind(audit_rows, "agent_baseline_approved")[-1]["replaced"] is True
    record = _stored()["agents"][AGENT]
    assert record["reported"] == {} and record["acknowledged"] == {}
    result = drift.check(AGENT, now=_JUDGED + 120)
    assert result["state"] == "within_baseline" and result["findings"] == []


def test_acknowledgements_are_bounded():
    entries = {f"k{n}": {"by": "dana", "at": float(n), "severity": "low"}
               for n in range(drift._MAX_ACKNOWLEDGED + 7)}
    kept = drift._newest(entries, "at", drift._MAX_ACKNOWLEDGED)
    assert len(kept) == drift._MAX_ACKNOWLEDGED and "k0" not in kept


# ------------------------------------------------------- check_all and views

def test_check_all_covers_every_enrolled_agent(alerts):
    _baselined("bot-a")
    _baselined("bot-b")
    _enroll("bot-c")
    _seed(_AFTER, "bot-a")
    _seed(_AFTER, "bot-b", runs=40)
    results = drift.check_all(now=_JUDGED)
    assert [(r["agent_id"], r["state"]) for r in results] == [
        ("bot-a", "within_baseline"), ("bot-b", "drifted"), ("bot-c", "no_baseline")]
    assert [a["detail"].split()[0] for a in alerts] == ["bot-b"]


def test_check_all_carries_on_past_one_agents_failure(monkeypatch, alerts):
    _baselined("bot-a")
    _baselined("bot-b")
    _seed(_AFTER, "bot-b", runs=40)
    real = drift._evaluate_record

    def flaky(agent_id, *args, **kw):
        if agent_id == "bot-a":
            raise RuntimeError("unexpected record shape")
        return real(agent_id, *args, **kw)

    monkeypatch.setattr(drift, "_evaluate_record", flaky)
    results = drift.check_all(now=_JUDGED)
    assert results[0] == {"agent_id": "bot-a",
                          "error": "The drift check for this agent did not finish."}
    assert results[1]["new_findings"] == ["volume:up"] and len(alerts) == 1


def test_check_all_refuses_to_guess_when_enrollment_cannot_be_read():
    _baselined()
    xa.registry_path().write_text("{ not json", encoding="utf-8")
    with pytest.raises(xa.ExternalAgentsDependencyError):
        drift.check_all(now=_JUDGED)
    with pytest.raises(xa.ExternalAgentsDependencyError):
        drift.roster_view(now=_JUDGED)


def test_roster_view_has_one_row_per_enrolled_agent():
    _baselined("bot-a")
    _baselined("bot-b")
    _enroll("bot-c")
    _seed(_AFTER, "bot-a")
    _seed(_AFTER, "bot-b", runs=40, tools={"crm_update": 14, "research": 5, "new_tool": 1})
    rows = drift.roster_view(now=_JUDGED)
    assert [row["agent_id"] for row in rows] == ["bot-a", "bot-b", "bot-c"]
    assert rows[0] == {
        "agent_id": "bot-a", "state": "within_baseline", "findings_count": 0,
        "highest_severity": "", "baseline_approved_at": _at(13, 23),
        "baseline_approved_by": "dana@corp.test", "last_observed_at": _at(17)}
    assert (rows[1]["state"], rows[1]["findings_count"], rows[1]["highest_severity"]) == (
        "drifted", 2, "high")
    assert rows[2] == {
        "agent_id": "bot-c", "state": "no_baseline", "findings_count": 0,
        "highest_severity": "", "baseline_approved_at": None,
        "baseline_approved_by": "", "last_observed_at": None}


def test_detail_gives_a_bounded_daily_series_for_charts():
    _enroll()
    drift.observe_discovered(AGENT, version_digest="digest-1", source="bedrock", now=_at(0))
    _seed(range(14))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    _seed(_AFTER, runs=40)
    out = drift.detail(AGENT, now=_JUDGED)
    assert out["state"] == "drifted" and _kinds(out) == {"volume"}
    assert out["baseline"]["approved_by"] == "dana@corp.test"
    assert out["current"]["runs"] == 120
    assert out["config"]["discovered"]["version_digest"] == "digest-1"
    assert out["last_observed_at"] == _at(17)
    series = out["series"]
    assert len(series) == drift._SERIES_DAYS
    assert series[-1] == {"day": drift._day_key(20_017), "runs": 40, "failures": 4,
                          "tool_calls": 80, "input_tokens": 0, "output_tokens": 0,
                          "screens": 20, "denials": 1, "approvals_required": 0,
                          "cost_dollars": 20.0}
    assert [row["day"] for row in series] == sorted(row["day"] for row in series)
    assert series[-4]["runs"] == 0  # a day with no activity is still on the chart
    json.dumps(out)


def test_detail_is_refused_for_an_agent_that_is_not_enrolled():
    with pytest.raises(drift.AgentDriftError, match="not enrolled"):
        drift.detail("ghost")
    _enroll()
    assert drift.detail(AGENT)["state"] == "no_baseline"


# ------------------------------------------------------ gateway integration

def test_every_screen_verdict_is_observed_exactly_once():
    _enroll(max_risk="high")
    assert xa.screen(AGENT, "crm_update", detail="update stage", risk="low")["allowed"]
    assert xa.screen(AGENT, "research")["rule"] == "allow"
    assert xa.screen(AGENT, "crm_update", risk="extreme")["rule"] == "bad_risk"
    assert xa.screen(AGENT, "not_my_tool", risk="low")["allowed"] is False
    parked = xa.screen(AGENT, "send_contract", detail="issue the contract", risk="high")
    assert parked["rule"] == "approval_required"
    day = _recorded()
    assert (day["screens"], day["denials"], day["approvals_required"]) == (5, 2, 1)
    assert day["tools"] == {"crm_update": 2, "research": 1, "not_my_tool": 1,
                            "send_contract": 1}
    assert (day["runs"], day["cost_dollars"]) == (0, 0.0)


def test_screens_while_contained_or_unenrolled_are_not_counted():
    _enroll()
    xa.screen(AGENT, "crm_update", risk="low")
    assert xa.contain(AGENT, contained_by="soc") is True
    assert xa.screen(AGENT, "crm_update", risk="low")["rule"] == "contained"
    assert xa.screen("ghost", "crm_update", risk="low")["rule"] == "not_in_registry"
    assert list(_stored()["agents"]) == [AGENT]
    day = _recorded()
    assert (day["screens"], day["denials"]) == (1, 0)


def test_reported_runs_are_observed_once_each():
    _enroll()
    run = {"title": "Quote for Northwind renewal", "outcome": "success",
           "summary": "Drafted and sent the renewal quote.", "steps": ["Pulled history"],
           "cost_dollars": 1.25, "input_tokens": 900, "output_tokens": 400,
           "tool_calls": 6, "tools": ["crm_update", "research"], "idempotency_key": "run-1",
           "declared": {"version": "1.4.2", "model": "model-a", "config_digest": "cfg-1"}}
    first = xa.record_run(AGENT, run)
    assert xa.record_run(AGENT, run)["duplicate"] is True  # a retry is not a second run
    xa.record_run(AGENT, {"title": "Quote attempt", "outcome": "failure",
                          "summary": "Pricing service unreachable.", "cost_dollars": 0.25})
    live = xa.start_run(AGENT, {"title": "Live quote"})
    xa.finish_run(AGENT, live["goal_id"], {"outcome": "success", "summary": "Sent.",
                                           "cost_dollars": 0.5, "tool_calls": 2,
                                           "tools": ["crm_update"]})
    assert first["goal_id"] != live["goal_id"]
    record = _stored()["agents"][AGENT]
    day = _recorded()
    assert (day["runs"], day["failures"], day["tool_calls"]) == (3, 1, 8)
    assert (day["input_tokens"], day["output_tokens"]) == (900, 400)
    assert day["cost_dollars"] == pytest.approx(2.0)
    assert day["tools"] == {"crm_update": 2, "research": 1}
    assert record["config"]["declared"]["model"] == "model-a"
    assert day["cost_dollars"] == pytest.approx(xa.roster()[0]["spent_dollars"])


def test_the_record_never_holds_what_the_agent_said():
    _enroll()
    canary = "NORTHWIND-CANARY-7731"
    xa.screen(AGENT, "crm_update", detail=f"update {canary}", risk="low")
    xa.record_run(AGENT, {"title": f"Quote {canary}", "outcome": "success",
                          "summary": f"Sent {canary}.", "steps": [f"Read {canary}"]})
    assert canary not in drift.store_path().read_text(encoding="utf-8")


def test_a_drift_failure_never_changes_a_governance_decision(monkeypatch):
    _enroll(max_risk="high")

    def boom(*_a, **_kw):
        raise RuntimeError("drift module is broken")

    monkeypatch.setattr(drift, "observe_screen", boom)
    monkeypatch.setattr(drift, "observe_run", boom)
    assert xa.screen(AGENT, "crm_update", risk="low") == {
        "allowed": True, "rule": "allow", "reason": "within ceilings"}
    assert xa.screen(AGENT, "crm_update", risk="extreme")["rule"] == "bad_risk"
    assert xa.screen(AGENT, "send_contract", risk="high")["requires_approval"] is True
    out = xa.record_run(AGENT, {"title": "Quote", "outcome": "success", "summary": "Sent.",
                                "cost_dollars": 1.0})
    assert out["over_budget"] is False
    live = xa.start_run(AGENT, {"title": "Live quote"})
    closed = xa.finish_run(AGENT, live["goal_id"], {"outcome": "success", "summary": "Sent."})
    assert closed["goal_id"] == live["goal_id"]
    assert xa.roster()[0]["runs"] == 2


def test_a_missing_drift_module_never_changes_a_governance_decision(monkeypatch):
    import importlib
    import sys

    import maverick
    _enroll()
    path = drift.store_path()
    monkeypatch.setitem(sys.modules, "maverick.agent_drift", None)
    monkeypatch.delattr(maverick, "agent_drift")
    with pytest.raises(ImportError):
        importlib.import_module("maverick.agent_drift")
    assert xa.screen(AGENT, "crm_update", risk="low")["rule"] == "allow"
    out = xa.record_run(AGENT, {"title": "Quote", "outcome": "success", "summary": "Sent."})
    assert out["goal_id"] > 0
    assert not path.exists()  # the hooks really were unreachable


def test_gateway_activity_end_to_end_reaches_a_finding(tmp_path, alerts):
    _configure(tmp_path, "[agent_drift]\nmin_screens = 3\nmin_runs = 1\n")
    _enroll(allow_tools=[*_TOOLS, "delete_records:low"])
    for _ in range(4):
        xa.screen(AGENT, "crm_update", risk="low")
    drift.approve_baseline(AGENT, actor="dana@corp.test")
    assert drift.check(AGENT)["state"] == "within_baseline"
    assert xa.screen(AGENT, "delete_records", risk="low")["allowed"] is True
    result = drift.check(AGENT)
    assert result["state"] == "drifted"
    assert result["new_findings"] == ["new_tool:delete_records"]
    assert alerts and "delete_records" in alerts[0]["detail"]


# ------------------------------------------------- defects found in review

def test_a_run_closed_while_the_agent_is_contained_is_not_counted():
    _enroll()
    started = xa.start_run(AGENT, {"title": "quote"})
    assert xa.contain(AGENT, contained_by="operator") is True
    xa.finish_run(AGENT, started["goal_id"], {"outcome": "success", "tools": ["wire_transfer"]})
    days = _stored()["agents"].get(AGENT, {}).get("days", {}) if drift.store_path().exists() else {}
    assert all(day.get("runs", 0) == 0 and day.get("failures", 0) == 0 for day in days.values())
    assert all("wire_transfer" not in day.get("tools", {}) for day in days.values())


def test_a_new_tool_is_still_new_when_the_baseline_held_uncounted_tools():
    _enroll()
    _seed(range(14))
    with drift._editing() as agents:
        drift._day_bucket(agents[AGENT], _at(3))["tools"]["(other)"] = 1
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    _seed(_AFTER)
    for _ in range(3):
        drift.observe_screen(AGENT, "db.exec(drop)", allowed=True, now=_at(16))
    result = drift.evaluate(AGENT, now=_JUDGED)
    unnamed = [f for f in result["findings"] if f["key"].startswith("new_tool:unnamed:")]
    assert len(unnamed) == 1 and unnamed[0]["severity"] == "high"
    assert "db.exec" not in json.dumps(result)  # the name itself is never shown or stored


def test_uncounted_tools_are_flagged_only_when_their_share_rises():
    _enroll()
    _seed(range(14))
    with drift._editing() as agents:
        drift._day_bucket(agents[AGENT], _at(3))["tools"]["(other)"] = 10
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    _seed(_AFTER)
    with drift._editing() as agents:
        drift._day_bucket(agents[AGENT], _at(16))["tools"]["(other)"] = 2
    assert "new_tool:(other)" not in {f["key"] for f in drift.evaluate(AGENT, now=_JUDGED)["findings"]}
    with drift._editing() as agents:
        drift._day_bucket(agents[AGENT], _at(16))["tools"]["(other)"] = 40
    assert "new_tool:(other)" in {f["key"] for f in drift.evaluate(AGENT, now=_JUDGED)["findings"]}


def test_a_declared_version_sent_as_a_number_is_still_compared():
    _enroll()
    _seed(range(14))
    drift.observe_run(AGENT, declared={"version": 1.4}, now=_at(13))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    drift.observe_run(AGENT, declared={"version": 2.0}, now=_at(16))
    assert "version_changed" in _kinds(drift.evaluate(AGENT, now=_JUDGED))
    assert drift._fingerprint(float("nan")) == "" and drift._fingerprint(True) == ""


def test_an_agent_enrolled_again_under_the_same_id_starts_clean(audit_rows):
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    drift.check(AGENT, now=_JUDGED)
    drift.acknowledge(AGENT, "new_tool:wire_transfer", actor="omar@corp.test", now=_JUDGED)
    assert xa.unenroll(AGENT, actor="admin@corp.test") is True
    assert AGENT not in _stored()["agents"]  # removal drops the record
    _enroll()
    assert drift.baseline(AGENT) is None
    assert drift.evaluate(AGENT, now=_JUDGED)["state"] == "no_baseline"


def test_a_leftover_record_from_an_earlier_enrollment_is_not_trusted():
    _baselined()
    # the record survives a removal that could not clear it (drift was off at the time)
    with xa._sidecar_locked():
        sidecar = xa._load_sidecar()
        sidecar[AGENT]["enrolled_at"] = sidecar[AGENT]["enrolled_at"] + 5000
        xa._save_sidecar(sidecar)
    assert drift.baseline(AGENT) is None
    assert drift.evaluate(AGENT, now=_JUDGED)["state"] == "no_baseline"
    assert drift.roster_view(now=_JUDGED)[0]["state"] == "no_baseline"
    drift.observe_screen(AGENT, "crm_update", allowed=True, now=_JUDGED)
    assert _stored()["agents"][AGENT]["baseline"] is None  # replaced, not inherited


def test_a_finding_that_appears_between_evaluation_and_reporting_waits_for_the_next_check(
        tmp_path, monkeypatch, audit_rows, alerts):
    _configure(tmp_path, "[agent_drift]\non_drift = \"contain\"\n")
    _baselined()
    _seed(_AFTER, cost_per_run=0.05)  # one low finding, so the check has something to report
    real = drift._report_new

    def late_arrival(agent_id, cfg, moment, **kw):
        # a new tool is screened after the check looked, before it reports
        with drift._editing() as agents:
            drift._day_bucket(agents[AGENT], _at(17))["tools"]["wire_transfer"] = 2
        return real(agent_id, cfg, moment, **kw)

    monkeypatch.setattr(drift, "_report_new", late_arrival)
    first = drift.check(AGENT, now=_JUDGED)
    assert first["new_findings"] == ["cost:down"] and first["contained"] is False
    assert "new_tool:wire_transfer" not in _stored()["agents"][AGENT]["reported"]
    monkeypatch.setattr(drift, "_report_new", real)
    second = drift.check(AGENT, now=_JUDGED + 60)
    assert second["new_findings"] == ["new_tool:wire_transfer"] and second["contained"] is True


def test_a_finding_whose_audit_row_was_not_written_is_reported_again(monkeypatch, alerts):
    _baselined()
    _seed(_AFTER, tools={"crm_update": 14, "research": 5, "wire_transfer": 1})
    monkeypatch.setattr(drift, "_audit", lambda *a, **kw: False)
    assert drift.check(AGENT, now=_JUDGED)["new_findings"] == []
    assert alerts == [] and _stored()["agents"][AGENT]["reported"] == {}
    monkeypatch.undo()


def test_nothing_is_approved_or_acknowledged_without_its_audit_row(monkeypatch):
    _enroll()
    _seed(range(14))
    monkeypatch.setattr(drift, "_audit", lambda *a, **kw: False)
    with pytest.raises(drift.AgentDriftError, match="audit log"):
        drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    assert _stored()["agents"][AGENT]["baseline"] is None


def test_an_acknowledgement_lapses_once_the_finding_has_been_gone_for_a_day(alerts):
    _baselined()
    _seed(range(15, 18), runs=40)
    drift.check(AGENT, now=_JUDGED)
    drift.acknowledge(AGENT, "volume:up", actor="omar@corp.test", now=_JUDGED)
    assert drift.evaluate(AGENT, now=_JUDGED)["findings_count"] == 0
    # the spike ends; three quiet days later the acknowledgement is dropped
    _seed(range(18, 24))
    drift.check(AGENT, now=_at(23, 23))
    assert "volume:up" not in _stored()["agents"][AGENT]["acknowledged"]
    # the same kind of spike later is a fresh finding, not a silenced one
    _seed(range(24, 27), runs=40)
    again = drift.check(AGENT, now=_at(26, 23))
    assert "volume:up" in again["new_findings"]


def test_a_baseline_with_no_whole_day_behind_it_does_not_judge_volume():
    _enroll()
    with drift._editing() as agents:
        record = drift._record_for(agents, AGENT, drift._enrolled_ids())
        drift._day_bucket(record, _at(0, 1))["runs"] = 12
        drift._day_bucket(record, _at(0, 1))["screens"] = 12
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(0, 6))
    with drift._editing() as agents:
        drift._day_bucket(agents[AGENT], _at(1))["runs"] = 12
    result = drift.evaluate(AGENT, now=_at(2, 1))
    assert "volume" in result["skipped"] and "volume" not in _kinds(result)


def test_checking_or_acknowledging_an_agent_that_is_not_enrolled_is_refused():
    with pytest.raises(drift.AgentDriftError):
        drift.check("ghost")
    with pytest.raises(drift.AgentDriftError):
        drift.acknowledge("ghost", "new_tool:x", actor="omar@corp.test")


def test_an_agent_that_stops_reporting_is_flagged_as_silent(tmp_path):
    _baselined()
    drift.observe_screen(AGENT, "crm_update", allowed=True, now=_at(14))
    quiet = drift.evaluate(AGENT, now=_at(14) + 47 * 3600)
    assert "silent" not in _kinds(quiet)
    result = drift.evaluate(AGENT, now=_at(14) + 49 * 3600)
    finding = _finding(result, "silent")
    assert finding["severity"] == "medium" and "reported nothing" in finding["summary"]
    _configure(tmp_path, "[agent_drift]\nsilent_hours = 200\n")
    assert "silent" not in _kinds(drift.evaluate(AGENT, now=_at(14) + 49 * 3600))


def test_an_agent_that_only_works_now_and_then_is_not_called_silent():
    _enroll()
    with drift._editing() as agents:
        record = drift._record_for(agents, AGENT, drift._enrolled_ids())
        for day in (0, 7):
            drift._day_bucket(record, _at(day))["runs"] = 3
    drift.observe_run(AGENT, now=_at(13))
    drift.approve_baseline(AGENT, actor="dana@corp.test", now=_at(13, 23))
    # about half a run a day: three days of quiet is usual for it
    assert "silent" not in _kinds(drift.evaluate(AGENT, now=_at(16, 23)))
