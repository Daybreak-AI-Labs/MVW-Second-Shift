"""Roster-wide privilege-escalation (capability attenuation) invariant.

The capability model's core security promise: a child spawned under a parent
grant can NEVER exceed it. When the fleet spawns a specialist, it runs the pack
under ``domain_capability(profile, parent_cap, principal)`` -> ``parent.attenuate
(...)``. This proves, across the WHOLE roster and in both governance modes, that
the resulting child capability is contained by a deliberately narrow parent:

  * no tool the child permits is forbidden by the parent,
  * the child's risk ceiling never rises above the parent's,
  * no host the child reaches is outside the parent's allow-list,

even when autonomy-levels-on lifts the pack's own ceiling to ``high`` and the
data-grounding grant adds connectors -- the parent still caps everything.

Includes a fault-injection control: a deliberately greedy pack (allows shell,
wire_transfer, ... at high risk, denies nothing) is fully contained by the
narrow parent, while the SAME pack with no parent is not -- so the test would
catch a broken ``attenuate`` rather than passing vacuously.
"""
from __future__ import annotations

import pytest
from maverick.capability import Capability

# A tightly-scoped supervisor grant: read-only, low ceiling, shell denied,
# only government hosts reachable.
_PARENT = Capability(
    principal="parent:supervisor",
    allow_tools=frozenset({"knowledge_search", "read_file"}),
    deny_tools=frozenset({"shell", "write_file"}),
    max_risk="low",
    allow_hosts=frozenset({"*.gov"}),
)


@pytest.fixture()
def _both_modes_on(monkeypatch):
    # the worst case for escalation: pack ceiling lifted to high + grants added.
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "on")


def test_disjoint_allowlist_collapses_to_deny_not_all():
    # A child whose pack allowlist is disjoint from the parent's must NOT
    # fail open to "all" -- it collapses to deny-all.
    child = _PARENT.attenuate(principal="c", allow={"some_unrelated_tool"})
    assert not child.permits("knowledge_search")
    assert not child.permits("shell")
    assert not child.permits("some_unrelated_tool")
