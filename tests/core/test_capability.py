"""Identity layer: signed, attenuating capabilities + enforcement.

Capabilities gate the tool surface per-agent. Children inherit an
*attenuated* (never broadened) grant, so a sub-agent cannot escalate past
its parent. Default-open: no capability set == unrestricted, behaviour
unchanged. Opt in via [capabilities] enforce or MAVERICK_ENFORCE_CAPABILITIES.
"""

import pytest

from maverick.capability import Capability, capability_enforced
from maverick.safety.tool_risk import tool_risk


def test_empty_allow_means_all():
    cap = Capability(principal="p")
    assert cap.permits("read_file") and cap.permits("shell")


def test_deny_beats_allow():
    cap = Capability(principal="p", allow_tools=frozenset({"shell"}),
                     deny_tools=frozenset({"shell"}))
    assert cap.permits("shell") is False


def test_allow_whitelist():
    cap = Capability(principal="p", allow_tools=frozenset({"read_file"}))
    assert cap.permits("read_file") is True
    assert cap.permits("shell") is False


def test_max_risk_ceiling():
    # shell is "high", read_file is "low" (see safety.tool_risk).
    cap = Capability(principal="p", max_risk="low")
    assert cap.permits("read_file") is True
    assert cap.permits("shell") is False


def test_knowledge_search_is_low_risk_lookup():
    cap = Capability(
        principal="p",
        allow_tools=frozenset({"knowledge_search"}),
        max_risk="low",
    )
    assert tool_risk("knowledge_search") == "low"
    assert cap.permits("knowledge_search") is True


def test_expiry():
    past = Capability(principal="p", expires_at=1000.0)
    assert past.permits("read_file", now=2000.0) is False
    assert past.permits("read_file", now=500.0) is True


def test_attenuate_rebinds_principal():
    child = Capability(principal="user:a").attenuate(principal="agent:coder-1")
    assert child.principal == "agent:coder-1"


def test_attenuate_records_revocation_lineage():
    root = Capability(principal="user:alice")
    child = root.attenuate(principal="agent:coder-1")
    grandchild = child.attenuate(principal="agent:reviewer-2")
    assert child.ancestors == ("user:alice",)
    assert grandchild.ancestors == ("user:alice", "agent:coder-1")
    assert grandchild.revocation_principals() == (
        "agent:reviewer-2", "agent:coder-1", "user:alice",
    )


def test_intersect_preserves_both_revocation_lineages():
    ambient = Capability(principal="agent:bob", ancestors=("user:bob",))
    handoff = Capability(principal="agent:bob", ancestors=("user:alice",))
    effective = ambient.intersect(handoff, principal="agent:bob")
    assert effective.ancestors == ("user:bob", "user:alice")
    assert effective.revocation_principals() == (
        "agent:bob", "user:alice", "user:bob",
    )


def test_child_signing_bytes_include_lineage():
    parent = Capability(principal="user:alice")
    child = parent.attenuate(principal="agent:coder-1")
    stripped = Capability(principal="agent:coder-1")
    assert b"ancestors" in child.signing_bytes()
    assert child.signing_bytes() != stripped.signing_bytes()


def test_attenuate_deny_grows():
    parent = Capability(principal="p", deny_tools=frozenset({"shell"}))
    child = parent.attenuate(deny={"computer"})
    assert {"shell", "computer"} <= set(child.deny_tools)
    assert not child.permits("shell") and not child.permits("computer")


def test_attenuate_allow_only_shrinks():
    # Parent allows all; child restricted to read_file.
    child = Capability(principal="p").attenuate(allow={"read_file"})
    assert child.allow_tools == frozenset({"read_file"})
    # Parent already restricted; child cannot ADD a tool back.
    parent = Capability(principal="p", allow_tools=frozenset({"read_file"}))
    child2 = parent.attenuate(allow={"read_file", "shell"})
    assert child2.allow_tools == frozenset({"read_file"})  # intersection only
    assert child2.permits("shell") is False


def test_attenuate_disjoint_tools_deny_all_not_allow_all():
    # Two restricted, non-overlapping tool allow-lists must NOT collapse to the
    # empty set (which would mean "all"); the child must permit no sampled tools.
    parent = Capability(principal="p", allow_tools=frozenset({"shell"}))
    child = parent.attenuate(allow={"read_file"})
    assert child.allow_tools != frozenset()  # not allow-all
    assert child.permits("shell") is False
    assert child.permits("read_file") is False
    assert child.permits("web_search") is False


def test_attenuate_max_risk_only_tightens():
    parent = Capability(principal="p", max_risk="high")
    assert parent.attenuate(max_risk="low").max_risk == "low"
    low = Capability(principal="p", max_risk="low")
    assert low.attenuate(max_risk="high").max_risk == "low"  # cannot loosen


def test_attenuation_is_subset_of_parent():
    # Every tool a child permits must also be permitted by the parent.
    parent = Capability(principal="p", deny_tools=frozenset({"computer"}),
                        max_risk="medium")
    child = parent.attenuate(principal="agent:x", deny={"write_file"}, max_risk="low")
    sample = ["read_file", "web_search", "shell", "computer", "write_file",
              "list_dir", "browser"]
    for t in sample:
        if child.permits(t):
            assert parent.permits(t), f"child escalated on {t}"


def test_empty_scopes_mean_all():
    cap = Capability(principal="p")
    assert cap.permits_path("/etc/passwd") and cap.permits_path("/repo/a.py")
    assert cap.permits_host("example.com") and cap.permits_host("10.0.0.1")


def test_permits_path_glob():
    cap = Capability(principal="p", allow_paths=frozenset({"/repo/*", "/tmp/*.log"}))
    assert cap.permits_path("/repo/src/main.py") is True
    assert cap.permits_path("/tmp/run.log") is True
    assert cap.permits_path("/etc/passwd") is False
    assert cap.permits_path("/tmp/run.txt") is False


def test_permits_host_glob():
    cap = Capability(principal="p", allow_hosts=frozenset({"*.example.com", "api.svc"}))
    assert cap.permits_host("a.example.com") is True
    assert cap.permits_host("api.svc") is True
    assert cap.permits_host("evil.com") is False
    assert cap.permits_host("example.com") is False  # no leading label


def test_attenuate_paths_restrict_from_all():
    # Parent unrestricted (all paths); child may be restricted to a subset.
    child = Capability(principal="p").attenuate(allow_paths={"/repo/*"})
    assert child.allow_paths == frozenset({"/repo/*"})
    assert child.permits_path("/repo/x") is True
    assert child.permits_path("/etc/x") is False


def test_attenuate_hosts_restrict_from_all():
    child = Capability(principal="p").attenuate(allow_hosts={"*.example.com"})
    assert child.allow_hosts == frozenset({"*.example.com"})
    assert child.permits_host("a.example.com") is True
    assert child.permits_host("evil.com") is False


def test_attenuate_paths_only_shrink():
    # Parent already restricted; child cannot add a path the parent lacked.
    parent = Capability(principal="p", allow_paths=frozenset({"/repo/*"}))
    child = parent.attenuate(allow_paths={"/repo/*", "/etc/*"})
    assert child.allow_paths == frozenset({"/repo/*"})  # intersection only
    assert child.permits_path("/etc/passwd") is False


def test_attenuate_hosts_only_shrink():
    parent = Capability(principal="p", allow_hosts=frozenset({"*.example.com"}))
    child = parent.attenuate(allow_hosts={"*.example.com", "evil.com"})
    assert child.allow_hosts == frozenset({"*.example.com"})
    assert child.permits_host("evil.com") is False


def test_attenuate_paths_inherited_when_unspecified():
    parent = Capability(principal="p", allow_paths=frozenset({"/repo/*"}),
                        allow_hosts=frozenset({"api.svc"}))
    child = parent.attenuate(principal="agent:x")
    assert child.allow_paths == frozenset({"/repo/*"})
    assert child.allow_hosts == frozenset({"api.svc"})


def test_attenuate_disjoint_scopes_deny_all_not_allow_all():
    # Two restricted, non-overlapping pattern sets must NOT collapse to the
    # empty set (which would mean "all"); the child must permit nothing.
    parent = Capability(principal="p", allow_paths=frozenset({"/repo/*"}))
    child = parent.attenuate(allow_paths={"/srv/*"})
    assert child.allow_paths != frozenset()  # not allow-all
    assert child.permits_path("/repo/x") is False
    assert child.permits_path("/srv/x") is False
    assert child.permits_path("/anything") is False


def test_attenuation_scopes_are_subset_of_parent():
    # Invariant: every path/host the child permits is also permitted by parent.
    parent = Capability(
        principal="p",
        allow_paths=frozenset({"/repo/*", "/tmp/*"}),
        allow_hosts=frozenset({"*.example.com", "api.svc"}),
    )
    child = parent.attenuate(
        principal="agent:x",
        allow_paths={"/repo/*"},
        allow_hosts={"*.example.com"},
    )
    paths = ["/repo/a", "/repo/b/c.py", "/tmp/x", "/etc/passwd", "/srv/y", "/"]
    for pth in paths:
        if child.permits_path(pth):
            assert parent.permits_path(pth), f"child escalated on path {pth}"
    hosts = ["a.example.com", "deep.sub.example.com", "api.svc", "evil.com",
             "example.com", "localhost"]
    for h in hosts:
        if child.permits_host(h):
            assert parent.permits_host(h), f"child escalated on host {h}"


def test_signing_bytes_includes_scopes():
    base = Capability(principal="p")
    scoped = Capability(principal="p", allow_paths=frozenset({"/repo/*"}),
                        allow_hosts=frozenset({"api.svc"}))
    # Distinct scopes must yield distinct signing payloads.
    assert base.signing_bytes() != scoped.signing_bytes()
    assert b"allow_paths" in scoped.signing_bytes()
    assert b"allow_hosts" in scoped.signing_bytes()
    # Stable + order-independent for the same logical grant.
    a = Capability(principal="p", allow_paths=frozenset({"/a", "/b"}))
    b = Capability(principal="p", allow_paths=frozenset({"/b", "/a"}))
    assert a.signing_bytes() == b.signing_bytes()


def test_enforced_via_env(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", "1")
    assert capability_enforced() is True


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    assert capability_enforced() is False


def test_enforced_via_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"capabilities": {"enforce": True}})
    assert capability_enforced() is True


def test_enforcement_policy_load_error_fails_closed(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)

    def _boom():
        raise RuntimeError("config unavailable")

    monkeypatch.setattr("maverick.config.load_config", _boom)
    assert capability_enforced() is True


@pytest.mark.parametrize("value", ["sometimes", "2", "enabled"])
def test_invalid_enforcement_env_fails_closed(monkeypatch, value):
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", value)
    assert capability_enforced() is True


def test_malformed_capability_section_fails_closed(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    monkeypatch.setattr(
        "maverick.config.load_config", lambda: {"capabilities": ["not", "a", "table"]},
    )
    assert capability_enforced() is True


def test_attenuating_globs_keeps_a_narrower_pattern_inside_the_parent():
    from maverick.capability import Capability

    parent = Capability(principal="p", allow_paths=frozenset({"src/*"}),
                        allow_hosts=frozenset({"*.example.com"}))
    child = parent.attenuate(allow_paths={"src/app/*", "docs/*"},
                             allow_hosts={"api.example.com"})
    assert child.permits_path("src/app/x.py") and not child.permits_path("docs/a.md")
    assert child.permits_host("api.example.com") and not child.permits_host("evil.test")
    # A pattern the parent cannot be shown to cover is not kept.
    assert not Capability(principal="p", allow_paths=frozenset({"a?"})).attenuate(
        allow_paths={"a*"}).permits_path("abc")
    assert not Capability(principal="p", allow_paths=frozenset({"*]b"})).attenuate(
        allow_paths={"[a]b"}).permits_path("ab")
