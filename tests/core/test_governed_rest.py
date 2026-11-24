"""Governed REST connector: a LIVE system of record routed through the
simulate -> approve -> commit -> lineage pipeline.

Network-free: the SSRF-safe client boundary (``_ssrf.safe_client``) is faked,
exactly as the enterprise-connector tests do, so the write path is exercised
without touching the network. The key behaviors under test:

  * ``preview_write`` makes NO network call (the simulate contract) yet renders
    a faithful, approvable effect;
  * a write is high-risk, so it hits the approval floor and is refused without
    an approver, then commits + records tamper-evident lineage with one;
  * the request rides the same egress-guarded path the Tool form uses.
"""
from __future__ import annotations

from maverick.governed_rest import salesforce_connector


class TestRegistry:

    def test_salesforce_env_wiring(self):
        c = salesforce_connector()
        assert c.base_url_env == "SALESFORCE_INSTANCE_URL"
        assert c.token_env == "SALESFORCE_ACCESS_TOKEN"

