"""Telemetry this process computes must reach the surface operators scrape.

Two gaps, both silent:

* ``tool_latency`` keeps per-tool p50/p95/p99 and ``provider_health`` keeps
  per-provider error rates, and neither was ever exported. An operator scraping
  /metrics could not see the two numbers they would actually alert on, on a
  platform that computes both.
* ``latency_budget.note_elapsed`` called ``record_metric`` with the name
  ``tool_latency_budget_exceeded``, which was never registered --
  ``record_metric`` returns silently for an unknown metric, so every breach was
  recorded into nothing.

These tests assert the values appear in a real scrape rather than that a
function was called, because "we call record_metric" was true the whole time
the metric did not exist.
"""

from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip(
    "prometheus_client", reason="observability extra not installed")


@pytest.fixture(autouse=True)
def _clean_profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))

    yield


def _scrape() -> str:
    """Render the computed collector exactly as a Prometheus scrape would."""
    from maverick import observability
    from prometheus_client import CollectorRegistry, generate_latest

    reg = CollectorRegistry()
    # Build the collector through the production path, then register it on an
    # isolated registry so the test does not depend on, or pollute, the global.
    captured = []
    monkey = type("R", (), {"register": lambda _self, c: captured.append(c)})()
    real_registry = None
    try:
        import prometheus_client

        real_registry = prometheus_client.REGISTRY
        prometheus_client.REGISTRY = monkey
        observability._register_computed_collector()
    finally:
        if real_registry is not None:
            prometheus_client.REGISTRY = real_registry
    assert captured, "the computed collector was not registered"
    reg.register(captured[0])
    return generate_latest(reg).decode("utf-8")


def test_an_empty_process_still_exports_the_series() -> None:
    """Zero-valued series from boot, so an alert can distinguish 0 from absent.

    A metric that only appears once it has a non-zero value cannot be alerted
    on: "no data" and "nothing wrong" render identically in a dashboard.
    """
    out = _scrape()
    for name in ("maverick_tool_latency_ms", "maverick_provider_error_rate",
                 "maverick_tool_latency_budget_breaches"):
        assert f"# HELP {name}" in out, name
