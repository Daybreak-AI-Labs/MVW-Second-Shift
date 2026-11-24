"""Tests for metrics and tracing (maverick.observability)."""
from __future__ import annotations
import sys
import types


def test_prometheus_exporter_defaults_to_loopback_bind(monkeypatch):
    import importlib

    monkeypatch.setenv("MAVERICK_PROMETHEUS_PORT", "9999")
    monkeypatch.delenv("MAVERICK_PROMETHEUS_ADDR", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)

    calls = {}

    def _start_http_server(port, *args, **kwargs):
        calls["port"] = port
        calls["args"] = args
        calls["kwargs"] = kwargs

    fake_prom = types.SimpleNamespace(
        Counter=lambda *a, **k: object(),
        Gauge=lambda *a, **k: object(),
        Histogram=lambda *a, **k: object(),
        start_http_server=_start_http_server,
    )
    monkeypatch.setitem(sys.modules, "prometheus_client", fake_prom)

    import maverick.observability as obs
    obs = importlib.reload(obs)
    monkeypatch.setattr(obs, "_initialized", False)
    monkeypatch.setattr(obs, "_metrics", {})
    obs._initialize()

    assert calls["port"] == 9999
    assert calls["kwargs"].get("addr") == "127.0.0.1"
