"""The benchmark reports all required performance failures to its caller."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from tools.load_check import OP_NAMES
from tools.mvw_benchmark import Workload, _TrafficClient, target_failures


def _sample(count, under, maximum=1, errors=None):
    return {"count": count, "under_target": under, "max_ms": maximum, "errors": errors or {}}


def _report():
    return {
        "serial": {name: _sample(4, 4, 199) for name in OP_NAMES},
        "burst": {name: _sample(100, 95) for name in OP_NAMES[:3]},
        "steady": {name: _sample(500, 480) for name in OP_NAMES},
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


def test_steady_agent_failures_and_missing_reports_fail_the_gate():
    report = _report()
    report["steady"]["Screen"]["errors"] = {"screen refused": 1}
    del report["steady"]["Report run"]
    assert target_failures(report) == ["An agent screen or run report failed during steady traffic."]


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", [{"allowed": False}, {"allowed": True, "requires_approval": True}, []])
async def test_load_driver_stops_when_screening_refuses_an_action(decision):
    paths = []

    def respond(request):
        paths.append(request.url.path)
        if request.url.path.endswith("/screen"):
            return httpx.Response(200, json=decision)
        return httpx.Response(201, json={"ok": True, "goal_id": 1})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond), base_url="http://127.0.0.1") as client:
        workload = Workload(client, "")
        await workload.agent({}, "only-report-if-allowed")
    assert paths == ["/api/v1/external/screen"]
    assert workload.report(200)["Screen"]["errors"] == {"screen refused": 1}


@pytest.mark.asyncio
async def test_successful_status_without_a_run_receipt_fails_the_load_check():
    replies = iter([{"allowed": True}, {"ok": True}])
    statuses = iter([200, 201])
    transport = httpx.MockTransport(lambda request: httpx.Response(next(statuses), json=next(replies)))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        workload = Workload(client, "")
        await workload.agent({}, "require-a-receipt")
    assert workload.report(200)["Report run"]["errors"] == {"unexpected reply": 1}


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


@pytest.mark.asyncio
async def test_load_driver_distinguishes_a_truncated_response_from_other_errors():
    pytest.importorskip("aiohttp")

    async def reply(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nshort")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(reply, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server, _TrafficClient(f"http://127.0.0.1:{port}", connections=1) as client:
        workload = Workload(client, "")
        assert not await workload.request("Home", "GET", "/", {})
    result = workload.report(1_000_000)["Home"]
    assert result["errors"] == {"ReadError": 1}
    assert result["under_target"] == 0
