"""The gate that keeps the egress guard's coverage claim true.

``egress_guard`` wraps ``httpx``, ``httpx2``, ``requests`` and ``urllib``,
which covers direct application calls plus provider SDK traffic. That claim has
exactly one way to quietly stop being true: someone adds a connector using a
client library the guard does not wrap.

That is not hypothetical. It is precisely how the previous design failed -- a
convention that authors had to remember, with nothing failing when they did
not, decaying to 87 ungated modules.
"""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("tool", ["webrtc", "websocket"])
def test_the_exfil_transports_carry_a_high_risk_tier(tool) -> None:
    from maverick.safety.tool_risk import _DEFAULT_RISK
    assert _DEFAULT_RISK.get(tool) == "high", tool
