"""Always-on, dependency-free runtime counters for Second Shift itself.

The platform ingests everyone else's telemetry; this is its own. A
thread-safe in-process registry with Prometheus text-format rendering
(format 0.0.4) and zero dependencies, so ``GET /metrics`` works on every
install — the opt-in :mod:`maverick.observability` exporter stays the
richer path when ``prometheus_client`` is present, and nothing here
duplicates its computed collectors: these are the platform's raw
operational counters (HTTP traffic, governed-record operations, gateway
decisions), which that module does not carry.

Cardinality is bounded per metric: past the cap, new label combinations
are dropped and the drop is itself counted — a runaway label can cost a
series, never the process.
"""
from __future__ import annotations

import threading

#: Distinct label combinations retained per metric.
MAX_SERIES_PER_METRIC = 200

_LOCK = threading.Lock()
_COUNTERS: dict[str, dict[str, object]] = {}


def _series_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(
        (str(key), str(value)[:120]) for key, value in labels.items()
    ))


def increment(
    name: str, *, amount: float = 1.0, help_text: str = "", **labels: str,
) -> None:
    """Add to a counter series, creating metric and series on first use."""

    global _DROPPED
    with _LOCK:
        metric = _COUNTERS.setdefault(
            name, {"help": help_text, "series": {}},
        )
        if help_text and not metric["help"]:
            metric["help"] = help_text
        series: dict = metric["series"]  # type: ignore[assignment]
        key = _series_key(labels)
        if key not in series and len(series) >= MAX_SERIES_PER_METRIC:
            _DROPPED += 1
            return
        series[key] = float(series.get(key, 0.0)) + float(amount)


__all__ = [
    "MAX_SERIES_PER_METRIC",
    "increment",
]
