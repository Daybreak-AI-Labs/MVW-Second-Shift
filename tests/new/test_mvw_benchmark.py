"""Load checks must exercise the promised workload and render real pages."""

import httpx
import pytest

from tools.mvw_benchmark import OP_NAMES, Workload, target_failures


def test_an_incomplete_run_cannot_pass_the_release_targets():
    one = {"count": 1, "under_target": 1, "max_ms": 1, "errors": {}}
    short = {name: dict(one) for name in OP_NAMES}

    assert target_failures({"serial": short, "steady": short, "burst": short})


@pytest.mark.asyncio
async def test_a_browser_error_page_with_status_200_is_not_a_success():
    async def error_page(_request):
        return httpx.Response(200, text="<title>Sign in · Second Shift</title>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(error_page), base_url="http://127.0.0.1") as client:
        work = Workload(client, "")
        await work.page("synthetic-session", 0)

    result = work.report(2000)["Home"]
    assert result["count"] == 1
    assert result["under_target"] == 0
    assert result["errors"] == {"wrong page": 1}
