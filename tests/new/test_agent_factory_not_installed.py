"""Without the runtime the factory says so plainly and the rest of Second Shift still works. This file never skips."""
from __future__ import annotations

import json
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    # Importing the runtime now raises ImportError, whether or not it is installed here.
    for name in [m for m in sys.modules if m == "second_shift_runtime" or m.startswith("second_shift_runtime.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "second_shift_runtime", None)
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        yield c
    config.reset_config_cache()


def test_the_factory_pages_say_it_is_not_installed(client):
    for path in ("/factory", "/factory/new"):
        page = client.get(path)
        assert page.status_code == 200 and "not installed" in page.text and "second-shift[factory]" in page.text, path
    assert client.get("/factory/FAC-anything").status_code == 503
    assert "not installed" in client.get("/factory/FAC-anything").json()["detail"]


def test_the_api_says_the_same_in_plain_words(client):
    status = client.get("/api/v1/factory/status")
    assert status.status_code == 200 and status.json() == {"installed": False}
    for method, path, body in (("get", "/api/v1/factory/agents", None), ("post", "/api/v1/factory/draft", {"brief": {"purpose": "x"}}),
                               ("post", "/api/v1/factory/agents", {"brief": {"purpose": "x"}, "parts": {}})):
        out = getattr(client, method)(path, **({"json": body} if body else {}))
        assert out.status_code == 503 and "not installed" in out.json()["detail"], path


def test_everything_else_still_works_and_the_server_never_needs_the_runtime(client):
    assert client.get("/external-agents").status_code == 200
    assert client.get("/approvals").status_code == 200
    assert client.get("/healthz").status_code in (200, 503)
    # The modules the approvals path and the drift check import load without the runtime.
    import maverick.factory.release as release
    import maverick.factory.store  # noqa: F401

    assert release.parse_action("factory_release:FAC-1:3") == ("FAC-1", 3) and release.parse_action("other:x:1") is None
    assert json.dumps(client.get("/api/v1/factory/status").json())
