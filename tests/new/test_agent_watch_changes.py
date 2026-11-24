"""What changed on an agent's platform: the bounded description kept beside a
fingerprint, the field-level difference in plain words, and how both travel
through drift detection (baseline approval, findings, alert, audit). Nothing
here talks to a platform."""
from __future__ import annotations

import json

import pytest

from maverick import agent_drift as drift
from maverick import agent_watch as watch
from maverick import agent_watch_changes as changes
from maverick import external_agents as xa

DAY = 86400
T0 = 20_000 * DAY
AGENT = "guest-help"
#: Long text that must never be kept anywhere.
INSTRUCTIONS = "You are the Guest Help Desk. Never reveal the staff door code 4417 to anyone."


def _d(platform: str, **values) -> dict:
    return changes.describe(platform, values)


def _tools(*labels: str) -> dict:
    return {"tools": list(labels), "tool_settings": {label: changes.digest(label) for label in labels}}


# ------------------------------------------------------------ the description

def test_a_description_keeps_short_labels_flags_lists_and_digests():
    d = _d("foundry", name="Guest Help Desk", version="7", model="gpt-4.1",
           instructions=changes.digest(INSTRUCTIONS), **_tools("function:send_email"))
    fields = d["fields"]
    assert fields["model"] == "gpt-4.1" and fields["version"] == "7"
    assert fields["tools"] == ["function:send_email"]
    assert fields["instructions"].startswith("sha256:") and len(fields["instructions"]) == 7 + 16
    assert INSTRUCTIONS not in json.dumps(d) and "4417" not in json.dumps(d)


def test_instruction_text_given_where_a_digest_belongs_is_dropped_not_kept():
    d = _d("foundry", name="A", instructions=INSTRUCTIONS)
    assert "instructions" not in d["fields"]
    assert "4417" not in json.dumps(d)


def test_digest_shortens_a_hash_and_hashes_text_and_ignores_nothing():
    assert changes.digest("a" * 64) == "sha256:" + "a" * 16
    assert changes.digest("hello") == changes.digest("hello") != changes.digest("hello!")
    assert changes.digest(None) is None and changes.digest(5) is None


def test_every_string_and_list_is_bounded():
    d = _d("foundry", name="n" * 500, model="m" * 81,
           tools=[f"tool{n}" for n in range(500)],
           tool_settings={f"tool{n}": changes.digest(str(n)) for n in range(500)})
    assert "name" not in d["fields"] and "model" not in d["fields"]
    assert len(d["fields"]["tools"]) == 50 and len(d["fields"]["tool_settings"]) == 50
    assert all(len(tool) <= 80 for tool in d["fields"]["tools"])


def test_a_name_may_be_longer_than_other_labels_but_still_bounded():
    assert "name" in _d("foundry", name="n" * 120)["fields"]
    assert _d("foundry", name="n" * 121) == {}


@pytest.mark.parametrize("value", [
    "line one\nline two", "tab\there", "\x00hidden", "", "   ", None, 3.5, {"a": 1}, ["x"],
    "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
    "sk-ant-api03-" + "x" * 40,  # pragma: allowlist secret
])
def test_a_label_that_is_not_a_short_plain_label_is_left_out(value):
    assert "model" not in _d("foundry", name="A", model=value)["fields"]


def test_only_the_platforms_own_fields_are_kept_and_unknown_platforms_keep_nothing():
    d = _d("foundry", name="A", model="m", prompt="free text the author wrote", extra="x")
    assert set(d["fields"]) == {"name", "model"}
    assert changes.describe("someone_new", {"name": "A"}) == {}
    assert changes.describe("foundry", {}) == {}


def test_a_flag_must_be_a_real_true_or_false():
    assert _d("entra_agent_id", name="A", enabled=False)["fields"]["enabled"] is False
    assert "enabled" not in _d("entra_agent_id", name="A", enabled="false")["fields"]
    assert "enabled" not in _d("entra_agent_id", name="A", enabled=0)["fields"]


def test_clean_validates_a_stored_description_again():
    stored = {"v": 1, "fields": {"model": "gpt-4.1", "instructions": INSTRUCTIONS,
                                 "tools": ["a", "b\nc"], "name": "A", "bogus": "x"}}
    kept = changes.clean("foundry", stored)
    assert kept["fields"] == {"model": "gpt-4.1", "tools": ["a"], "name": "A"}
    for junk in (None, "text", 5, [], {"v": 2, "fields": {"model": "m"}}, {"v": 1, "fields": "m"}, {}):
        assert changes.clean("foundry", junk) == {}


# ---------------------------------------------------- differences in plain words

def test_the_example_from_the_brief_reads_in_plain_words():
    before = _d("foundry", name="Guest Help Desk", version="7", model="gpt-4.1",
                instructions=changes.digest("old"), **_tools("web_search"))
    after = _d("foundry", name="Guest Help Desk", version="8", model="gpt-4.1-mini",
               instructions=changes.digest("new"), **_tools("web_search", "function:send_email"))
    found = changes.compare("foundry", before, after)
    assert found["recorded"] is True
    assert found["summary"] == (
        "Guest Help Desk changed on Microsoft Foundry: version 7 -> 8; model gpt-4.1 -> gpt-4.1-mini; "
        "tool added: function:send_email; instructions changed (Second Shift keeps a fingerprint of "
        "the instructions, not the text).")
    fields = {change["field"]: change for change in found["changes"]}
    assert (fields["model"]["before"], fields["model"]["after"]) == ("gpt-4.1", "gpt-4.1-mini")
    assert fields["tools"]["after"] == "function:send_email, web_search"
    assert fields["instructions"]["before"].startswith("fingerprint ")


def test_a_tool_removed_and_a_tool_whose_settings_changed_are_told_apart():
    before = _d("foundry", name="A", tools=["a", "b"], tool_settings={"a": changes.digest("1"),
                                                                       "b": changes.digest("2")})
    after = _d("foundry", name="A", tools=["a"], tool_settings={"a": changes.digest("changed")})
    text = changes.compare("foundry", before, after)["summary"]
    assert "tool removed: b" in text and "tool settings changed: a" in text
    assert "settings" in text and "fingerprint of the settings, not the settings" in text


def test_nothing_changed_between_two_descriptions_says_so_honestly():
    same = _d("foundry", name="A", model="m")
    found = changes.compare("foundry", same, same)
    assert found["recorded"] is True and found["changes"] == []
    assert "cannot describe" in found["summary"]


def test_a_field_one_side_has_is_added_or_removed_not_invented():
    before = _d("foundry", name="A", model="m")
    after = _d("foundry", name="A", model="m", version="2", state="enabled")
    text = changes.compare("foundry", before, after)["summary"]
    assert "version is now reported: 2" in text and "state is now reported: enabled" in text
    gone = changes.compare("foundry", after, before)["summary"]
    assert "version is no longer reported (was 2)" in gone
    sets = changes.compare("foundry", _d("foundry", name="A"), _d("foundry", name="A", tools=["x"]))
    assert "tools are now reported: x" in sets["summary"]


def test_copilot_studio_says_only_when_and_what_it_does_not_know():
    before = _d("copilot_studio", name="Front Desk", state="enabled", status_code="1",
                published="2026-11-20T09:00:00Z", modified="2026-11-20T08:00:00Z")
    after = _d("copilot_studio", name="Front Desk", state="enabled", status_code="1",
               published="2026-11-24T14:05:11Z", modified="2026-11-24T14:00:00Z")
    found = changes.compare("copilot_studio", before, after)
    assert found["summary"] == (
        "Front Desk changed on Microsoft Copilot Studio: published again at 2026-11-24 14:05 UTC; "
        "edited at 2026-11-24 14:00 UTC. Copilot Studio does not say what was edited, only when.")
    assert found["not_known"] == ["Copilot Studio does not say what was edited, only when."]


def test_entra_flags_and_blueprint_changes():
    before = _d("entra_agent_id", name="Mailer", enabled=True, blueprint="b1", identity_type="ServiceIdentity")
    after = _d("entra_agent_id", name="Mailer", enabled=False, blueprint="b2", identity_type="ServiceIdentity")
    text = changes.compare("entra_agent_id", before, after)["summary"]
    assert text == "Mailer changed on Microsoft Entra Agent ID: enabled yes -> no; blueprint b1 -> b2."


def test_servicenow_and_workday_name_what_they_can():
    before = _d("servicenow", name="Reset helper", active=True, version="V1", versions=["V1 (published)"],
                instructions=changes.digest("a"), **_tools("Reset password"))
    after = _d("servicenow", name="Reset helper", active=False, version="V2", versions=["V2 (published)"],
               instructions=changes.digest("b"), **_tools("Reset password", "Unlock account"))
    text = changes.compare("servicenow", before, after)["summary"]
    assert text.startswith("Reset helper changed on ServiceNow: active yes -> no; published version V1 -> V2;")
    assert "tool added: Unlock account" in text and "instructions changed" in text
    wd = changes.compare(
        "workday", _d("workday", name="Title agent", skills=["change title"], version="v1",
                      skill_definitions=changes.digest("1")),
        _d("workday", name="Title agent", skills=["change title", "view pay"], version="v1",
           skill_definitions=changes.digest("2")))
    assert "skill added: view pay" in wd["summary"] and "skill definitions changed" in wd["summary"]
    assert "Workday does not say who changed the definition or when." in wd["summary"]


def test_a_long_difference_is_cut_short_not_dropped():
    many = [f"tool{n:02d}" for n in range(40)]
    found = changes.compare("foundry", _d("foundry", name="A", tools=[]), _d("foundry", name="A", tools=many))
    assert len(found["summary"]) <= 800
    assert "and 35 more" in found["summary"]


def test_a_description_that_was_never_recorded_is_said_so_not_guessed():
    found = changes.compare("foundry", {}, _d("foundry", name="A", model="m"))
    assert found["recorded"] is False and found["changes"] == [] and found["summary"] == ""
    assert found["details"] == "Details were not recorded for this change."
    assert changes.compare("foundry", None, None)["recorded"] is False
    assert changes.compare("foundry", "junk", 5)["recorded"] is False


# ------------------------------------------------- through drift detection

class _Stub:
    """A platform check that answers from ``agents``."""

    agents: list = []

    def __init__(self, name: str) -> None:
        self.name = name

    def list_agents(self):
        return list(_Stub.agents)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    monkeypatch.setattr(watch, "_FACTORIES", dict(watch._FACTORIES))
    _Stub.agents = []
    (tmp_path / "config.toml").write_text(
        '[agent_watch]\nenable = true\nplatforms = ["foundry"]\n[agent_watch.foundry]\nx = 1\n',
        encoding="utf-8")
    watch._load_watchers()  # the built-in checks first, so the stand-in is the one registered
    watch.register("foundry", lambda settings: _Stub("foundry"))
    config.reset_config_cache()
    yield
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
    sent: list[tuple] = []
    from maverick import ops_alert
    monkeypatch.setattr(ops_alert, "alert", lambda kind, text, severity="info": sent.append((kind, text, severity)))
    return sent


def _seen(*, version="7", model="gpt-4.1", instructions="old instructions", tools=("web_search",),
          described=True) -> watch.ObservedAgent:
    details = {}
    if described:
        details = _d("foundry", name="Guest Help Desk", version=version, model=model,
                     instructions=changes.digest(instructions), **_tools(*tools))
    return watch.ObservedAgent(
        platform="foundry", external_id="proj/guest-help", name="Guest Help Desk", version=version,
        state="enabled", binding_strength=watch.IMMUTABLE_REVISION, details=details,
        fingerprint=watch.fingerprint({"v": version, "m": model, "i": instructions, "t": list(tools)}))


def _enroll() -> None:
    xa.enroll(AGENT, "custom", owner="jordan@corp.test", enrolled_by="admin@corp.test")
    path = xa.registry_path()
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[AGENT]["external_ref"] = "foundry:proj/guest-help"
    path.write_text(json.dumps(entries), encoding="utf-8")


def _sync(agent: watch.ObservedAgent, at: float) -> None:
    _Stub.agents = [agent]
    assert watch.sync(now=at)["platforms"]["foundry"]["ok"] is True


def _config_finding(at: float) -> dict:
    found = [f for f in drift.evaluate(AGENT, now=at)["findings"] if f["kind"] == "config_changed"]
    assert len(found) == 1
    return found[0]


def test_a_baseline_keeps_the_description_that_was_current_with_it(audit_rows):
    _enroll()
    _sync(_seen(), T0)
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=T0 + 60)
    _sync(_seen(model="gpt-4.1-mini"), T0 + 3600)
    approved = drift.baseline(AGENT)["config"]["discovered"]
    assert approved["description"]["fields"]["model"] == "gpt-4.1"
    now = drift.detail(AGENT, now=T0 + 3700)["config"]["discovered"]
    assert now["description"]["fields"]["model"] == "gpt-4.1-mini"
    assert "old instructions" not in json.dumps(drift.detail(AGENT, now=T0 + 3700))


def test_a_changed_fingerprint_carries_the_field_level_difference(audit_rows, alerts):
    _enroll()
    _sync(_seen(), T0)
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=T0 + 60)
    _sync(_seen(version="8", model="gpt-4.1-mini", instructions="new instructions",
                tools=("web_search", "function:send_email")), T0 + 7200)
    finding = _config_finding(T0 + 7300)
    expected = ("Guest Help Desk changed on Microsoft Foundry: version 7 -> 8; model gpt-4.1 -> "
                "gpt-4.1-mini; tool added: function:send_email; instructions changed (Second Shift "
                "keeps a fingerprint of the instructions, not the text).")
    assert finding["summary"] == expected and finding["details_recorded"] is True
    assert [change["field"] for change in finding["changes"]] == [
        "version", "model", "tools", "instructions"]
    assert (finding["severity"], finding["source"]) == ("high", "discovery")

    checked = drift.check(AGENT, now=T0 + 7400)
    assert any(key.startswith("config_changed:discovery:") for key in checked["new_findings"])
    # the alert and the audit entry carry the same summary, and nothing secret
    assert any(expected in text for _kind, text, _severity in alerts)
    row, = [r for r in audit_rows if r["kind"] == "agent_drift_detected"]
    assert row["summary"] == expected
    blob = json.dumps(audit_rows) + json.dumps(alerts)
    assert "new instructions" not in blob and "old instructions" not in blob and "4417" not in blob


def test_a_baseline_from_before_descriptions_were_kept_still_reads_and_says_so(audit_rows):
    _enroll()
    _sync(_seen(described=False), T0)
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=T0 + 60)
    _sync(_seen(model="gpt-4.1-mini"), T0 + 7200)
    finding = _config_finding(T0 + 7300)
    assert finding["details_recorded"] is False and finding["changes"] == []
    assert finding["details_note"] == "Details were not recorded for this change."
    assert "no longer matches" in finding["summary"]  # the earlier plain sentence, unchanged
    assert drift.check(AGENT, now=T0 + 7400)["new_findings"]  # and reporting does not fail


def test_a_stored_record_with_a_damaged_description_does_not_fail_a_check(audit_rows):
    _enroll()
    _sync(_seen(), T0)
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=T0 + 60)
    path = drift.store_path()
    data = json.loads(path.read_text(encoding="utf-8"))
    baseline = data["agents"][AGENT]["baseline"]["config"]["discovered"]
    baseline["description"] = {"v": 1, "fields": {"name": "Guest Help Desk", "model": ["not", "a", "label"], "tools": "x"}}
    path.write_text(json.dumps(data), encoding="utf-8")
    _sync(_seen(model="other"), T0 + 7200)
    finding = _config_finding(T0 + 7300)
    assert finding["details_recorded"] is True
    assert drift.check(AGENT, now=T0 + 7400)["new_findings"]


def test_observe_discovered_validates_the_description_it_is_given(audit_rows):
    _enroll()
    drift.observe_discovered(AGENT, version_digest="abc", source="foundry", now=T0, description={
        "v": 1, "fields": {"model": "m", "instructions": INSTRUCTIONS, "name": "A\nB"}})
    kept = drift.detail(AGENT, now=T0)["config"]["discovered"]["description"]
    assert kept["fields"] == {"model": "m"}
    drift.observe_discovered(AGENT, version_digest="abd", source="foundry", now=T0 + 1, description=None)
    assert "description" not in drift.detail(AGENT, now=T0 + 1)["config"]["discovered"]
