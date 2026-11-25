"""The benchmark reports all required performance failures to its caller."""
from __future__ import annotations

import httpx
import pytest

from tools.load_check import OP_NAMES
from tools.mvw_benchmark import Workload, target_failures


def _sample(count, under, maximum=1, errors=None):
    return {"count": count, "under_target": under, "max_ms": maximum, "errors": errors or {}}


def _report():
    return {
        "serial": {name: _sample(4, 4, 199) for name in OP_NAMES},
        "burst": {name: _sample(100, 95) for name in OP_NAMES[:3]},
        "steady": {name: _sample(500, 480) for name in (*OP_NAMES[:3], "Teams card")},
        "overload": {"Screen": _sample(100, 95), "Report run": _sample(100, 95)},
    }


def test_exact_thresholds_and_transport_failures_are_failures():
    report = _report()
    assert target_failures(report) == []
    report["serial"]["Screen"]["max_ms"] = 200
    report["burst"]["Home"]["under_target"] = 94
    report["steady"]["Teams card"]["errors"] = {"TransportError": 1}
    report["overload"]["Report run"]["errors"] = {"503 gateway busy": 1}
    assert len(target_failures(report)) == 4


@pytest.mark.asyncio
async def test_quick_error_does_not_count_as_a_page_under_target():
    replies = iter([200, 503])
    transport = httpx.MockTransport(lambda request: httpx.Response(next(replies)))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        workload = Workload(client, "")
        await workload.page("test-session", 0)
        await workload.page("test-session", 0)
    result = workload.report(1_000_000)["Home"]
    assert result["count"] == 2
    assert result["errors"] == {"503": 1}
    assert result["under_target"] == 1
