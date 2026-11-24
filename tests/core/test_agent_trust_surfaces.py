"""Agent identity and trust gating on the external surfaces.

Covers A2A per-caller bearer -> agent identity + admission + ceiling, the
gRPC, MCP and marketplace surfaces, and governance gating on federation
delegation (DENY + fail-closed REQUIRE_HUMAN)."""
from __future__ import annotations
from maverick import agent_trust
from maverick.agent_trust import TrustedAgent


def test_agent_for_a2a_token_resolves():
    reg = {"vega": TrustedAgent(id="vega", a2a_token="s3cret"),
           "other": TrustedAgent(id="other", a2a_token="zzz")}
    assert agent_trust.agent_for_a2a_token("s3cret", registry=reg).id == "vega"
    assert agent_trust.agent_for_a2a_token("nope", registry=reg) is None
    assert agent_trust.agent_for_a2a_token("", registry=reg) is None
    # An entry with no a2a_token never matches the empty default.
    assert agent_trust.agent_for_a2a_token("", registry={"x": TrustedAgent(id="x")}) is None


def test_agent_for_a2a_token_rejects_inactive_or_outbound_only_entries():
    reg = {
        "revoked": TrustedAgent(id="revoked", a2a_token="revoked-token", revoked=True),
        "expired": TrustedAgent(id="expired", a2a_token="expired-token", expires_at=1),
        "future": TrustedAgent(id="future", a2a_token="future-token", not_before=9_999_999_999),
        "outbound": TrustedAgent(id="outbound", a2a_token="outbound-token", direction="outbound"),
    }
    for token in reg:
        assert agent_trust.agent_for_a2a_token(f"{token}-token", registry=reg) is None


def test_a2a_token_parses_from_config():
    reg = agent_trust.load_registry({"agent_trust": {"agents": [
        {"id": "vega", "a2a_token": "tok-123"},
    ]}})
    assert reg["vega"].a2a_token == "tok-123"


def test_external_agent_allowlist_does_not_implicitly_gain_coordination():
    from maverick.capability import COORDINATION_TOOLS

    entry = TrustedAgent(
        id="reader",
        allow_tools=frozenset({"read_file", "send_to_agent"}),
    )
    cap = entry.capability()

    assert cap.permits("read_file")
    assert cap.permits("send_to_agent")
    assert all(
        not cap.permits(tool)
        for tool in COORDINATION_TOOLS - {"send_to_agent"}
    )


def test_token_surface_isolation():
    # A token configured for one surface must not authenticate another.
    reg = {"vega": TrustedAgent(id="vega", grpc_token="g", mcp_token="m",
                                a2a_token="a")}
    assert agent_trust.agent_for_token("g", "grpc", registry=reg).id == "vega"
    assert agent_trust.agent_for_token("g", "mcp", registry=reg) is None
    assert agent_trust.agent_for_token("g", "a2a", registry=reg) is None
    assert agent_trust.agent_for_token("m", "mcp", registry=reg).id == "vega"


def test_duplicate_active_surface_token_is_not_an_identity():
    reg = {
        "vega": TrustedAgent(id="vega", mcp_token="duplicate"),
        "sirius": TrustedAgent(id="sirius", mcp_token="duplicate"),
    }

    assert agent_trust.agent_for_token("duplicate", "mcp", registry=reg) is None


def test_duplicate_token_ignores_inactive_entries():
    reg = {
        "vega": TrustedAgent(id="vega", grpc_token="duplicate"),
        "revoked": TrustedAgent(
            id="revoked", grpc_token="duplicate", revoked=True,
        ),
    }

    assert agent_trust.agent_for_token(
        "duplicate", "grpc", registry=reg,
    ).id == "vega"
