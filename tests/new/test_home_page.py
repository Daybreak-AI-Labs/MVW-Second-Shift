"""The home page: what needs the signed-in person today.

Hermetic. Each person signs in as in ``signin_kit`` and every answer comes from
the real routes of the web app. The page must show each person only what their
permissions allow, survive any one source failing, run no check and send no
alert, and escape everything an agent or a platform supplied.
"""
from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

from tests.new import signin_kit as kit
from tests.new.signin_kit import ROLES

NAME = "Refund <script>alert(1)</script> bot"
SECTIONS = {"approvals", "drift", "agents", "platforms", "keys", "alerts"}
#: Which sections each role gets, from the permission each section needs.
EXPECTED = {
    "admin": SECTIONS,
    "governance_lead": {"approvals", "drift", "agents", "platforms"},
    "operator": {"approvals", "drift", "agents", "platforms"},
    "approver": {"approvals", "drift", "agents", "platforms"},
    "responder": {"drift", "agents", "platforms"},
    "auditor": {"drift", "agents", "platforms"},
    "viewer": {"drift", "agents", "platforms"},
}
DAY = 86400


@pytest.fixture(scope="module")
def signing_key():
    return kit.new_key()


@pytest.fixture
def installation(tmp_path, monkeypatch, request, signing_key):
    stop = kit.start(tmp_path, monkeypatch, request, signing_key)
    yield tmp_path
    stop()


@pytest.fixture
def app():
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def person(installation, app, signing_key):
    def client(role: str) -> TestClient:
        return kit.client_for(app, signing_key, role)
    return client


class Platform:
    """A platform that lists whatever the test put in ``agents``."""

    name = "fake"
    agents: list = []

    def __init__(self, settings: dict) -> None:
        pass

    def list_agents(self):
        return list(Platform.agents)


def _everything_needing_attention(person, tmp_path, monkeypatch):
    """One of each thing the page reports, made through the real routes."""
    from maverick import (
        agent_drift,
        agent_watch,
        agent_watch_microsoft,  # noqa: F401 -- registers the built-in checks
        external_agents,
    )
    from maverick_dashboard._shared import _world

    boss = person("admin")
    kit.configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = ["fake"]\n')
    monkeypatch.setattr(agent_watch, "_FACTORIES", {**agent_watch._FACTORIES, "fake": Platform})
    Platform.agents = [agent_watch.ObservedAgent(
        platform="fake", external_id="a-1", name="Invoice <i>helper</i>", version="1",
        state="enabled", fingerprint=agent_watch.fingerprint({"c": "1"}))]

    def enroll(agent_id, **extra):
        made = boss.post("/api/v1/external-agents", json={"id": agent_id, "platform": "copilot", "owner": "ops@example.com", **extra})
        assert made.status_code == 201, made.text

    enroll("helpdesk", description=NAME)
    enroll("billing", max_dollars=1.0)
    enroll("payroll")
    enroll("expiring", expires_days=5)
    enroll("later", expires_days=40)
    external_agents.contain("helpdesk", contained_by="user:admin")
    external_agents.record_run("billing", {"title": "Run", "outcome": "success", "summary": "work", "cost_dollars": 3.0})
    paused = boss.post("/api/v1/agent-control-plane/principals/suspend", json={"principal": "agent:payroll", "reason": "check"})
    assert paused.status_code == 200, paused.text
    # drift: a baseline from a normal week, then a tool never seen before
    now = time.time()
    for back in range(8, 0, -1):
        for _ in range(4):
            agent_drift.observe_screen("payroll", "lookup_policy", allowed=True, now=now - back * DAY)
        agent_drift.observe_run("payroll", cost_dollars=0.2, tool_calls=4, outcome="success", tools=("lookup_policy",),
                                declared={"version": "1", "model": "m1"}, now=now - back * DAY)
    assert boss.post("/api/v1/external-agents/payroll/drift/baseline", json={}).status_code == 200
    for _ in range(5):
        agent_drift.observe_screen("payroll", "export_records", allowed=True, now=now)
    # a request waiting for a decision, and a platform check with an agent nobody added
    world = _world()
    world.create_approval("external:helpdesk:send <b>contract</b>", risk="high", provenance="external_agents",
                          requested_by="agent:helpdesk")
    assert boss.post("/api/v1/agent-watch/sync").status_code == 200


def _home(client) -> str:
    page = client.get("/")
    assert page.status_code == 200, page.text
    return page.text


def _shown(html: str) -> set[str]:
    return set(re.findall(r'id="home-([a-z]+)" aria-labelledby', html))


# ------------------------------------------------------------- who sees what

@pytest.mark.parametrize("role", ROLES)
def test_each_role_sees_exactly_the_sections_its_permissions_allow(person, installation, monkeypatch, role):
    _everything_needing_attention(person, installation, monkeypatch)
    html = _home(person(role))
    assert _shown(html) == EXPECTED[role]
    # what a section would have said is not on the page for a role that may not see it
    assert ("Waiting for your decision" in html) == ("approvals" in EXPECTED[role])
    assert ("Access keys that are ending" in html) == ("keys" in EXPECTED[role])
    assert ("Alerts are switched off" in html) == ("alerts" in EXPECTED[role])
    assert ("/approvals#approval-" in html) == ("approvals" in EXPECTED[role])


def test_the_sidebar_offers_home_to_everyone_and_approvals_only_to_those_who_may_decide(person):
    for role in ROLES:
        html = _home(person(role))
        assert 'href="/"' in html
        assert ('href="/approvals"' in html) == (role in {"admin", "governance_lead", "operator", "approver"}), role


def test_page_admission_and_navigation_share_one_current_visibility_read(person, monkeypatch):
    from maverick import record_documents
    from maverick_dashboard import ui_visibility

    viewer = person("viewer")
    path = ui_visibility.store_path()
    read_text = record_documents.RecordDocument.read_text
    reads = []

    def count(document):
        if document.path == path:
            reads.append(document.path)
        return read_text(document)

    def sidebar():
        return _home(viewer).split('<aside class="sidebar"', 1)[1].split("</aside>", 1)[0]

    monkeypatch.setattr(record_documents.RecordDocument, "read_text", count)
    assert 'href="/external-agents"' in sidebar()
    assert len(reads) == 1
    record_documents.at(path).write_text('{"/external-agents":{"viewer":false}}')
    assert 'href="/external-agents"' not in sidebar()
    assert len(reads) == 2
    assert viewer.get("/external-agents").status_code == 403


def test_each_item_links_to_where_it_is_fixed(person, installation, monkeypatch):
    _everything_needing_attention(person, installation, monkeypatch)
    html = _home(person("admin"))
    assert re.search(r'href="/approvals#approval-\d+"', html)
    assert 'href="/external-agents/payroll#agent-drift"' in html
    assert 'href="/external-agents/helpdesk"' in html and 'href="/external-agents/billing"' in html
    assert 'href="/external-agents/expiring"' in html
    assert 'href="/external-agents#platform-checks"' in html and 'href="/external-agents#alert-delivery"' in html


def test_what_needs_attention_is_named_in_plain_words(person, installation, monkeypatch):
    _everything_needing_attention(person, installation, monkeypatch)
    html = _home(person("admin"))
    assert "is blocked for breaking rules" in html
    assert "billing is over its budget" in html
    assert "payroll is paused" in html
    assert "payroll: " in html and "export_records" in html
    assert "is on Fake but nobody added it here" in html
    assert "expiring&#39;s access ends on" in html
    assert "later&#39;s access" not in html  # forty days away is not yet worth a line
    assert "Alerts are switched off" in html


def test_the_most_serious_comes_first(person, installation, monkeypatch):
    _everything_needing_attention(person, installation, monkeypatch)
    agents = _home(person("admin")).split('id="home-agents"', 1)[1].split("</ul>", 1)[0]
    assert agents.index("blocked for breaking rules") < agents.index("over its budget")


def test_home_formats_only_the_five_highest_priority_visible_approvals(monkeypatch):
    from types import SimpleNamespace

    from maverick.safety import secret_detector
    from maverick_dashboard import _shared, content_access, home_page

    approvals = [SimpleNamespace(id=index, action=f"Request {index}", requested_at=index,
                                 risk="critical" if index < 4 else "medium", provenance="external_agents")
                 for index in range(10)]
    world = SimpleNamespace(pending_approvals=lambda: approvals)
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr(content_access, "readable_approvals", lambda request, rows, world: rows[1:])
    formatted = []
    redact = secret_detector.redact

    def track(text):
        formatted.append(text)
        return redact(text)

    monkeypatch.setattr(secret_detector, "redact", track)
    section = {}
    home_page._approvals(section, None)
    assert [item["href"] for item in section["lines"]] == [f"/approvals#approval-{index}" for index in (3, 2, 1, 9, 8)]
    assert section["count"] == 9
    assert formatted == [item["text"] for item in section["lines"]]


# ----------------------------------------------------------------- escaping

def test_names_and_reasons_from_agents_and_platforms_are_escaped(person, installation, monkeypatch):
    _everything_needing_attention(person, installation, monkeypatch)
    html = _home(person("admin"))
    for raw in ("<script>alert(1)</script>", "<i>helper</i>", "<b>contract</b>"):
        assert raw not in html, raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Invoice &lt;i&gt;helper&lt;/i&gt;" in html
    assert "&lt;b&gt;contract&lt;/b&gt;" in html


# -------------------------------------------------------------- empty states

def test_with_nothing_wrong_it_says_so_and_says_what_is_watched(person, installation):
    html = _home(person("viewer"))
    assert "All clear" in html and "Nothing needs you right now" in html
    assert "Second Shift is watching" in html and "changes in how agents behave" in html
    assert 'id="home-agents"' not in html


def test_an_administrator_with_working_alerts_and_nothing_wrong_sees_all_clear(person, installation, monkeypatch):
    monkeypatch.setenv("TEAMS_NOTIFY_WEBHOOK_URL", "https://prod-00.example.invalid/workflows/abc?sig=s3cr3t-signature")  # pragma: allowlist secret
    kit.configure(installation, '[alerts]\nenabled = true\nbackends = ["teams"]\n')
    html = _home(person("admin"))
    assert "Nothing needs you right now" in html and "that alerts can reach people" in html
    assert "s3cr3t-signature" not in html


def test_alerts_that_are_on_with_nowhere_to_go_are_flagged_for_an_administrator(person, installation):
    kit.configure(installation, "[alerts]\nenabled = true\n")
    assert "Alerts are on but have nowhere to go" in _home(person("admin"))
    assert "nowhere to go" not in _home(person("viewer"))


def test_turned_off_outside_agents_are_not_listed_or_claimed_to_be_watched(person, installation, monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    html = _home(person("viewer"))
    assert "Nothing is being watched yet" in html and "changes in how agents behave" not in html
    assert "All clear" in html


# ----------------------------------------------------- one source failing

def _boom(*args, **kwargs):
    raise RuntimeError("the record is unreadable")


FAILURES = {
    "approvals": ("Requests waiting for a decision could not be read.", "world"),
    "drift": ("Drift findings could not be read.", "maverick.agent_drift:roster_view"),
    "agents": ("Outside agents could not be read.", "maverick.external_agents:roster"),
    "platforms": ("Platform checks could not be read.", "maverick.agent_watch:status"),
    "keys": ("Access key dates could not be read.", "maverick.agent_trust:load_registry"),
    "alerts": ("Alert settings could not be read.", "maverick.ops_alert:delivery_status"),
}


@pytest.mark.parametrize("source", sorted(FAILURES))
def test_one_source_failing_says_so_and_the_rest_still_render(person, installation, monkeypatch, source):
    _everything_needing_attention(person, installation, monkeypatch)
    message, target = FAILURES[source]
    if target == "world":
        from maverick.world_model import WorldModel

        monkeypatch.setattr(WorldModel, "pending_approvals", _boom)
    else:
        module, name = target.split(":")
        monkeypatch.setattr(__import__(module, fromlist=[name]), name, _boom)
    page = person("admin").get("/")
    assert page.status_code == 200
    html = page.text
    assert message in html
    # every other message is absent unless that source needs the failed one
    # the access key dates, the platform checks and the agent list all read the roster
    needs = {"agents": {"agents", "platforms", "keys"}, "keys": {"agents", "platforms", "keys"}}.get(source, {source})
    for other, (other_message, _) in FAILURES.items():
        if other not in needs:
            assert other_message not in html, (source, other)
    assert "All clear" not in html
    # what could still be read is shown
    assert SECTIONS - needs <= _shown(html)


def test_a_failing_source_is_not_reported_as_all_clear(person, installation, monkeypatch):
    monkeypatch.setattr("maverick.agent_drift.roster_view", _boom)
    html = _home(person("viewer"))
    assert "Drift findings could not be read." in html
    assert "All clear" not in html and "Nothing needs you right now" not in html


# ----------------------------------------------------------- only reads

def test_loading_the_page_runs_no_check_and_sends_no_alert(person, installation, monkeypatch):
    from maverick import agent_drift, agent_watch, ops_alert

    _everything_needing_attention(person, installation, monkeypatch)
    for module, name in ((agent_drift, "check"), (agent_drift, "check_all"), (agent_drift, "acknowledge"),
                         (agent_drift, "approve_baseline"), (agent_watch, "sync"), (ops_alert, "alert"), (ops_alert, "send_test")):
        monkeypatch.setattr(module, name, lambda *a, **k: pytest.fail("the home page must only read"))
    before = _log_size()
    for role in ROLES:
        assert person(role).get("/").status_code == 200
    assert _log_size() == before


def _log_size() -> int:
    from maverick.audit import default_audit_log

    root = default_audit_log().audit_dir
    return sum(path.stat().st_size for path in root.glob("*.ndjson")) if root.exists() else 0


def test_nothing_is_cached_between_requests(person, installation, monkeypatch):
    client = person("admin")
    first = client.get("/")
    assert first.headers["cache-control"] == "private, no-store"
    assert "Waiting for your decision" not in first.text
    from maverick_dashboard._shared import _world

    _world().create_approval("external:helpdesk:send_contract", risk="medium", provenance="external_agents", requested_by="agent:helpdesk")
    assert "Waiting for your decision" in client.get("/").text


def test_the_page_answers_no_one_who_is_not_signed_in(installation, app):
    anonymous = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    assert anonymous.get("/").status_code in {302, 303, 401, 403}


def test_when_sign_in_is_off_the_local_owner_sees_everything(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_ALERTS"):
        monkeypatch.delenv(name, raising=False)
    from maverick_dashboard.app import app

    html = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/").text
    assert _shown(html) == {"alerts"}  # alerts are off by default; nothing else needs the owner
    assert 'href="/audit"' in html and 'href="/approvals"' in html


def test_keys_ending_soon_count_each_agent_once_and_sort_the_soonest_first(person, installation):
    boss = person("admin")
    for agent_id, days in (("far", 13), ("near", 2), ("gone", 0.00001)):
        assert boss.post("/api/v1/external-agents", json={"id": agent_id, "platform": "copilot", "owner": "o@example.com",
                                                          "expires_days": days}).status_code == 201
    time.sleep(1.0)  # the shortest key was set to last under a second
    keys = _home(boss).split('id="home-keys"', 1)[1].split("</ul>", 1)[0]
    assert keys.index("gone") < keys.index("near") < keys.index("far")
    assert "access ended on" in keys


def test_page_reuses_a_roster_once_and_reads_another_process_update(person, installation, monkeypatch):
    import subprocess
    import sys

    from maverick import external_agents

    admin = person("admin")
    enrolled = admin.post("/api/v1/external-agents", json={
        "id": "process-test", "platform": "custom", "description": "Process test agent",
    })
    assert enrolled.status_code == 201
    original = external_agents.roster
    reads = []

    def counted(*args, **kwargs):
        reads.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(external_agents, "roster", counted)
    assert "Process test agent is blocked for breaking rules" not in _home(admin)
    assert len(reads) == 1
    subprocess.run(
        [sys.executable, "-c", "from maverick.external_agents import contain; "
         "assert contain('process-test', contained_by='user:admin')"],
        check=True, timeout=15, capture_output=True,
    )
    assert "Process test agent is blocked for breaking rules" in _home(admin)
    assert len(reads) == 2
