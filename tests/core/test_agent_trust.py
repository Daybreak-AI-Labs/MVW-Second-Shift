"""Agent Trust Plane: the single registry + decision point for external
agents. Covers registry parsing (fail-closed on junk), the engaged/disengaged
posture, inbound/outbound/direction/capability/budget decisions, pinned-key
identity verification, data-scope gating, and the federation + A2A wiring."""
from __future__ import annotations

import pytest
from maverick import agent_trust
from maverick.agent_trust import (
    TrustedAgent,
    clamp_budget,
    decide_inbound,
    decide_outbound,
    load_registry,
)


def test_load_registry_parses_entries():
    cfg = {"agent_trust": {"agents": [
        {"id": "vega", "pubkey": "ab" * 32, "direction": "both",
         "allow_tools": ["read_file", "http_fetch"], "max_risk": "medium",
         "max_dollars": 2.0, "max_wall_seconds": 600, "data_scopes": ["support"]},
        {"id": "copilot", "direction": "inbound", "allow_tools": ["research"]},
    ]}}
    reg = load_registry(cfg)
    assert set(reg) == {"vega", "copilot"}
    vega = reg["vega"]
    assert vega.pubkey == "ab" * 32
    assert vega.allow_tools == frozenset({"read_file", "http_fetch"})
    assert vega.max_dollars == 2.0
    assert vega.data_scopes == frozenset({"support"})
    assert reg["copilot"].pubkey == ""  # no pinned key is allowed (migration)


def test_load_registry_is_fail_closed_on_junk():
    cfg = {"agent_trust": {"agents": [
        "not-a-table",
        {"id": "BAD ID"},                      # invalid charset -> skipped
        {"id": "x", "pubkey": "nothex"},       # bad pubkey -> entry dropped
        {"id": "y", "direction": "sideways"},  # bad direction -> entry dropped
        {"id": "dup", "max_risk": "low"},
        {"id": "dup", "max_risk": "high"},     # duplicate -> first wins
    ]}}
    reg = load_registry(cfg)
    assert set(reg) == {"dup"}
    assert reg["dup"].max_risk == "low"


def test_load_registry_empty_when_absent_or_malformed():
    assert load_registry({}) == {}
    assert load_registry({"agent_trust": {"agents": "oops"}}) == {}


@pytest.mark.parametrize(("field", "bad"), [
    ("pubkey", ""),
    ("pubkey", 123),
    ("direction", "sideways"),
    ("direction", ["both"]),
    ("max_risk", "critical"),
    ("max_risk", None),
    ("max_dollars", 0),
    ("max_dollars", -1),
    ("max_dollars", float("nan")),
    ("max_dollars", float("inf")),
    ("max_dollars", "-inf"),
    ("max_wall_seconds", True),
    ("max_wall_seconds", "not-a-number"),
    ("allow_tools", 123),
    ("allow_tools", ["read_file", 123]),
    ("allow_tools", [""]),
    ("deny_tools", {"shell": True}),
    ("deny_tools", [None]),
    ("data_scopes", 123),
    ("data_scopes", ["support", ""]),
])
def test_present_malformed_security_field_drops_entry(field, bad):
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", field: bad},
    ]}})
    assert "v" not in reg


def test_absent_optional_security_fields_remain_valid():
    reg = load_registry({"agent_trust": {"agents": [{"id": "v"}]}})
    assert reg["v"] == TrustedAgent(id="v")


def test_load_trust_state_propagates_config_loader_failure(monkeypatch):
    from maverick import config

    def _broken_config():
        raise OSError("config unreadable")

    monkeypatch.setattr(config, "load_config", _broken_config)
    with pytest.raises(OSError, match="config unreadable"):
        agent_trust.load_trust_state()


def test_load_trust_state_fails_closed_on_corrupt_active_toml(tmp_path, monkeypatch):
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text("[agent_trust\nenforce = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    config.reset_config_cache()
    try:
        with pytest.raises(agent_trust.AgentTrustError, match="source is unreadable"):
            agent_trust.load_trust_state()
    finally:
        config.reset_config_cache()


def test_load_trust_state_rejects_non_table_config_root(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", list)
    with pytest.raises(agent_trust.AgentTrustError, match="root must be a table"):
        agent_trust.load_trust_state()


def test_load_trust_state_rejects_non_table_trust_section(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"agent_trust": []})
    with pytest.raises(agent_trust.AgentTrustError, match="section must be a table"):
        agent_trust.load_trust_state()


def test_load_registry_non_table_config_is_empty():
    assert load_registry([]) == {}
    assert load_registry({"agent_trust": []}) == {}


def test_enforced_env_overrides(monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "1")
    assert agent_trust.agent_trust_enforced() is True
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "0")
    assert agent_trust.agent_trust_enforced() is False


def test_enforced_rejects_malformed_env_and_config(monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "definitely")
    with pytest.raises(agent_trust.AgentTrustError, match="recognized boolean"):
        agent_trust.agent_trust_enforced({})

    monkeypatch.delenv("MAVERICK_AGENT_TRUST")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    with pytest.raises(agent_trust.AgentTrustError, match="must be a boolean"):
        agent_trust.agent_trust_enforced({
            "agent_trust": {"enforce": "false"},
        })


def test_enforced_follows_enterprise_mode(monkeypatch):
    monkeypatch.delenv("MAVERICK_AGENT_TRUST", raising=False)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert agent_trust.agent_trust_enforced() is True


def test_disengaged_is_a_noop_allow():
    # No registry, no ceiling, always allowed -> existing deployments unchanged.
    d = decide_inbound("anybody", requested_tools=["shell"], enforced=False)
    assert d.allowed and d.rule == "disabled" and d.capability is None
    assert decide_outbound("anybody", enforced=False).allowed


def _reg(*agents: TrustedAgent) -> dict[str, TrustedAgent]:
    return {a.id: a for a in agents}


def test_inbound_unknown_agent_denied_when_engaged():
    d = decide_inbound("ghost", registry={}, enforced=True)
    assert d.denied and d.rule == "not_in_registry"


def test_inbound_direction_enforced():
    reg = _reg(TrustedAgent(id="out", direction="outbound"))
    d = decide_inbound("out", registry=reg, enforced=True)
    assert d.denied and d.rule == "direction"


def test_inbound_capability_ceiling_blocks_unpermitted_tool():
    reg = _reg(TrustedAgent(id="vega", allow_tools=frozenset({"read_file"})))
    d = decide_inbound("vega", requested_tools=["shell"], registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


def test_inbound_allows_within_ceiling_and_returns_capability():
    reg = _reg(TrustedAgent(id="vega", allow_tools=frozenset({"read_file"}),
                            max_risk="medium"))
    d = decide_inbound("vega", requested_tools=["read_file"], registry=reg,
                       enforced=True)
    assert d.allowed and d.rule == "allow"
    assert d.capability is not None
    assert d.capability.permits("read_file")
    assert not d.capability.permits("shell")


def test_inbound_risk_above_ceiling_denied():
    reg = _reg(TrustedAgent(id="vega", max_risk="low"))
    d = decide_inbound("vega", max_risk="high", registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


def test_outbound_unknown_denied_known_allowed():
    assert decide_outbound("ghost", registry={}, enforced=True).denied
    reg = _reg(TrustedAgent(id="vega", direction="both"))
    assert decide_outbound("vega", registry=reg, enforced=True).allowed
    reg2 = _reg(TrustedAgent(id="inb", direction="inbound"))
    assert decide_outbound("inb", registry=reg2, enforced=True).denied


def test_clamp_budget_takes_the_tighter_bound():
    a = TrustedAgent(id="v", max_dollars=2.0, max_wall_seconds=600)
    assert clamp_budget(a, max_dollars=5.0, max_wall_seconds=300) == (2.0, 300)
    assert clamp_budget(a, max_dollars=1.0) == (1.0, 600)
    assert clamp_budget(None, max_dollars=5.0) == (5.0, None)


def test_permits_scope():
    a = TrustedAgent(id="v", data_scopes=frozenset({"support"}))
    assert a.permits_scope(None)        # unscoped query carries no department
    assert a.permits_scope("support")
    assert not a.permits_scope("finance")
    assert not TrustedAgent(id="w").permits_scope("support")  # empty == none


def test_inbound_revoked_agent_denied():
    reg = _reg(TrustedAgent(id="v", revoked=True))
    d = decide_inbound("v", registry=reg, enforced=True)
    assert d.denied and d.rule == "revoked"


def test_inbound_expired_agent_denied():
    reg = _reg(TrustedAgent(id="v", expires_at=1.0))  # epoch 1970
    d = decide_inbound("v", registry=reg, enforced=True)
    assert d.denied and d.rule == "expired"


def test_inbound_not_yet_valid_denied():
    reg = _reg(TrustedAgent(id="v", not_before=4_102_444_800.0))  # year 2100
    d = decide_inbound("v", registry=reg, enforced=True)
    assert d.denied and d.rule == "not_yet_valid"


def test_outbound_revoked_denied():
    reg = _reg(TrustedAgent(id="v", revoked=True))
    assert decide_outbound("v", registry=reg, enforced=True).rule == "revoked"


def test_capability_inherits_entry_expiry():
    cap = TrustedAgent(id="v", expires_at=123.0).capability()
    assert cap.expires_at == 123.0


def test_lifecycle_fields_parse_from_config():
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", "expires_at": 999.0, "not_before": 1.0, "revoked": True},
    ]}})
    assert reg["v"].expires_at == 999.0
    assert reg["v"].not_before == 1.0
    assert reg["v"].revoked is True


def test_absent_lifecycle_fields_mean_no_bound():
    # Missing not_before/expires_at is legitimate (no bound) -> entry kept.
    reg = load_registry({"agent_trust": {"agents": [{"id": "v"}]}})
    assert reg["v"].expires_at is None
    assert reg["v"].not_before is None


@pytest.mark.parametrize("bad", ["not-a-date", 0, -5, "2026-13-99", ""])
def test_malformed_expiry_fails_closed(bad):
    # A present-but-malformed lifecycle bound must NOT coerce to "never expires"
    # (that would mint an immortal credential). Fail closed: drop the entry, so
    # the agent is simply untrusted rather than permanently valid.
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", "expires_at": bad},
    ]}})
    assert "v" not in reg


def test_malformed_not_before_fails_closed():
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", "not_before": "garbage"},
    ]}})
    assert "v" not in reg


def test_inbound_max_risk_case_insensitive_ceiling():
    # "HIGH" must be normalised and caught against a "low" ceiling, not waved
    # through because the case didn't match the lowercase risk set.
    reg = _reg(TrustedAgent(id="v", max_risk="low"))
    d = decide_inbound("v", max_risk="HIGH", registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


def test_inbound_unrecognised_risk_refused():
    reg = _reg(TrustedAgent(id="v", max_risk="high"))
    d = decide_inbound("v", max_risk="bogus", registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


def test_decide_memory_access_unscoped_denied():
    from maverick.agent_trust import decide_memory_access
    reg = _reg(TrustedAgent(id="v", data_scopes=frozenset({"support"})))
    assert decide_memory_access("v", None, registry=reg, enforced=True).denied
    assert decide_memory_access("v", "", registry=reg, enforced=True).denied


def test_decide_memory_access_scope_enforced():
    from maverick.agent_trust import decide_memory_access
    reg = _reg(TrustedAgent(id="v", data_scopes=frozenset({"support"})))
    assert decide_memory_access("v", "finance", registry=reg, enforced=True).denied
    assert decide_memory_access("v", "support", registry=reg, enforced=True).allowed
    # Disengaged is a no-op allow regardless of scope.
    assert decide_memory_access("v", None, registry=reg, enforced=False).allowed


def test_verify_identity_rejects_revoked():
    reg = _reg(TrustedAgent(id="vega", pubkey="ab" * 32, revoked=True))
    ok, reason = agent_trust.verify_identity(
        "vega", {"origin": "vega", "schema": "maverick-test/1"},
        expected_schema="maverick-test/1", registry=reg)
    assert not ok and "revoked" in reason
