"""Durable, secret-free incident delivery with a stand-in for ServiceNow."""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("SECOND_SHIFT_SN_TEST_ID", "fixture-client")
    monkeypatch.setenv("SECOND_SHIFT_SN_TEST_SECRET", "fixture-credential")
    (tmp_path / "config.toml").write_text(
        '[servicenow_incidents]\nenabled = true\ninstance = "https://example.service-now.com"\n'
        'client_id_env = "SECOND_SHIFT_SN_TEST_ID"\nclient_secret_env = "SECOND_SHIFT_SN_TEST_SECRET"\n'
        'close_code = "Integration resolved"\n', encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_off_host_settings_refuse_delivery(setup):
    from maverick import config
    from maverick import servicenow_incidents as sn

    path = setup / "config.toml"
    path.write_text(path.read_text().replace("example.service-now.com", "example.com"))
    config.reset_config_cache()
    assert sn.status()["problem"]


def test_event_coalesces_and_reconciles_lost_create_response(setup, monkeypatch):
    from maverick import agent_watch, ops_alert
    from maverick import servicenow_incidents as sn

    calls = []
    rows = {}
    clock = [100.0]
    monkeypatch.setattr(sn, "_now", lambda: clock[0])
    monkeypatch.setattr(agent_watch, "client_credentials_token", lambda *args, **kwargs: "fixture-token")

    def service(method, url, **kwargs):
        calls.append(method)
        if method == "POST":
            payload = kwargs["json_body"]
            assert "fixture-credential" not in json.dumps(payload)
            assert "an-agent" not in json.dumps(payload)
            key = payload["u_second_shift_correlation_id"]
            rows[key] = {**payload, "sys_id": "a" * 32, "state": "1"}
            raise agent_watch.WatchError("response lost")
        if method == "GET":
            rule = parse_qs(urlsplit(url).query).get("sysparm_query")
            if rule is None:
                result = next(iter(rows.values()))
            else:
                key = rule[0].split("=")[1]
                result = [rows[key]] if key in rows else []
            return 200, json.dumps({"result": result}).encode()
        assert method == "PATCH" and urlsplit(url).path.endswith("a" * 32)
        patch = kwargs["json_body"]
        assert patch["state"] == "6" and patch["close_code"] == "Integration resolved"
        row = next(iter(rows.values()))
        row.update(patch)
        return 200, json.dumps({"result": row}).encode()

    monkeypatch.setattr(agent_watch, "_request", service)
    for _ in range(2):
        ops_alert.incident("blocked", "an-agent", cause="rule")
    assert sn.status()["pending"] == 1

    sn.deliver_due()
    assert sn.status()["retrying"] == 1
    sn.deliver_due()
    assert calls == ["GET", "POST"]

    clock[0] += 901
    sn.deliver_due()
    assert calls == ["GET", "POST", "GET"]
    assert sn.status()["pending"] == 0

    ops_alert.incident("blocked", "an-agent", resolve=True)
    sn.deliver_due()
    assert calls[-1] == "PATCH"
    assert sn.status()["pending"] == 0 and len(rows) == 1


def test_missing_settings_leave_alerts_unchanged(tmp_path, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "unset.toml"))
    ops_alert.incident("emergency")
    assert "servicenow" not in ops_alert.delivery_status()


def test_delivery_uses_the_guarded_client_for_oauth_and_table_calls(setup, monkeypatch):
    import httpx

    from maverick import agent_watch, ops_alert
    from maverick import servicenow_incidents as sn
    from maverick.tools import _ssrf

    calls = []

    def reply(request):
        calls.append((request.method, request.url.path))
        if request.url.path == "/oauth_token.do":
            assert parse_qs(request.content.decode()) == {
                "grant_type": ["client_credentials"], "client_id": ["fixture-client"],
                "client_secret": ["fixture-credential"],
            }
            return httpx.Response(200, json={"access_token": "opaque-fixture", "token_type": "Bearer"})
        assert request.headers["authorization"] == "Bearer opaque-fixture"
        if request.method == "GET":
            return httpx.Response(200, json={"result": []})
        incident = json.loads(request.content)
        return httpx.Response(201, json={"result": {
            "sys_id": "a" * 32, "state": "1", "u_second_shift_correlation_id": incident["u_second_shift_correlation_id"],
        }})

    def safe_client(url, *, timeout):
        assert urlsplit(url).netloc == "example.service-now.com" and 0 < timeout <= 10
        return httpx.Client(transport=httpx.MockTransport(reply), timeout=timeout, follow_redirects=False)

    monkeypatch.setattr(agent_watch, "_TOKENS", {})
    monkeypatch.setattr(_ssrf, "safe_client", safe_client)
    ops_alert.incident("emergency")
    sn.deliver_due()
    assert ops_alert.delivery_status()["servicenow"]["pending"] == 0
    assert calls == [("POST", "/oauth_token.do"), ("GET", "/api/now/table/incident"), ("POST", "/api/now/table/incident")]


def test_blocked_incident_opens_only_when_the_agent_is_contained(setup, monkeypatch):
    """A single refused action is a normal outcome, not an incident. The incident
    opens once, when repeated rule breaks contain the agent, and the release that
    resolves it is the same event that ends the containment."""
    from contextlib import nullcontext

    from maverick import external_agents as xa
    from maverick import ops_alert

    sidecar = {"an-agent": {}}
    monkeypatch.setattr(xa, "_sidecar_locked", nullcontext)
    monkeypatch.setattr(xa, "_load_sidecar", lambda **_: sidecar)
    monkeypatch.setattr(xa, "_save_sidecar", lambda _entries: None)
    monkeypatch.setattr(xa, "_screen_verdict", lambda *_args, **_kwargs: {})
    opened = []
    monkeypatch.setattr(ops_alert, "incident", lambda *args, **kwargs: opened.append((args, kwargs)))

    for _ in range(xa._CONTAIN_DENIALS - 1):
        xa._deny_and_count("an-agent", "send_email", "ceiling", "too risky")
    assert opened == []

    xa._deny_and_count("an-agent", "send_email", "ceiling", "too risky")
    assert sidecar["an-agent"]["contained"] is True
    assert opened == [(("blocked", "an-agent"), {})]

    xa._deny_and_count("an-agent", "send_email", "ceiling", "too risky")
    assert len(opened) == 1
