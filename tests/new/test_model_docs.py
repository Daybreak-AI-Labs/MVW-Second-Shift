"""The short example in docs/model-drift.md runs, against the real routes."""
from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

DOC = Path(__file__).resolve().parents[2] / "docs" / "model-drift.md"


def test_the_documented_example_runs_and_uses_only_httpx(tmp_path, monkeypatch):
    from maverick import governed_records, world_model

    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard.app import app

    block = re.search(r"```python\n(.*?)```", DOC.read_text(encoding="utf-8"), re.S).group(1)
    imports = set(re.findall(r"^(?:import|from) (\w+)", block, re.M))
    assert imports == {"os", "random", "httpx"}

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as admin:
        assert admin.post("/api/v1/external-agents", json={"id": "helpdesk", "platform": "copilot",
                                                           "owner": "ops@example.com"}).status_code == 201
        key = admin.post("/api/v1/external-agents/helpdesk/credentials", json={"surface": "rest"}).json()["token"]
        agent = TestClient(app, base_url="http://127.0.0.1")
        assert agent.post("/api/v1/external/runs", headers={"Authorization": f"Bearer {key}"},
                          json={"title": "t", "outcome": "success", "declared": {"model": "claude-sonnet"}}).status_code == 201
        monkeypatch.setenv("SECOND_SHIFT_URL", "http://127.0.0.1")
        monkeypatch.setenv("SECOND_SHIFT_AGENT_KEY", key)
        monkeypatch.setattr(httpx, "Client", lambda **kw: TestClient(app, base_url=kw["base_url"], headers=kw["headers"]))
        printed: list = []
        exec(compile(block, "docs/model-drift.md", "exec"), {"print": printed.append})  # noqa: S102
        assert printed and printed[0]["awaiting_approval"] is True
        (model,) = admin.get("/api/v1/models").json()["models"]
        assert model["status"] == "awaiting_approval"


@pytest.mark.parametrize("word", ["Lightwork", "Daybreak", "Maverick"])
def test_the_page_says_second_shift(word):
    assert word not in DOC.read_text(encoding="utf-8")
