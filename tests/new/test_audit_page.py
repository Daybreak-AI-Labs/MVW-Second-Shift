"""The audit trail page: who may read it, what it shows, its filters, paging, export and integrity check.

Hermetic. Each person signs in as in ``signin_kit``. Days written by hand hold
plain rows in the audit folder the app reads; rows written through the app's own
audit writer are signed, so the integrity check has a real chain to verify.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from tests.new import signin_kit as kit
from tests.new.signin_kit import ROLES

MAY_READ = {"admin", "governance_lead", "auditor"}


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


def _ts(day: str, hour: int = 9, minute: int = 0) -> float:
    return datetime.fromisoformat(f"{day}T{hour:02d}:{minute:02d}:00+00:00").astimezone(timezone.utc).timestamp()


def _row(kind: str, day: str, minute: int = 0, writer: str = "external_agents", **fields) -> dict:
    return {"v": 2, "ts": _ts(day, 9, minute), "kind": kind, "agent": writer, "goal_id": None, **fields}


def _write_day(root, day: str, rows: list[dict]) -> None:
    folder = root / "audit"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{day}.ndjson").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _log_rows(root) -> list[dict]:
    rows = []
    for path in sorted((root / "audit").glob("*.ndjson")):
        rows += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows


def _lines(html: str) -> list[str]:
    """The "what happened" cell of each row of the entries table, in order."""
    if "<tbody>" not in html:
        return []
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    said = []
    for row in re.findall(r"<tr>(.*?)</tr>", body, re.S):
        cells = re.findall(r"<td>(.*?)</td>", row, re.S)
        said.append(re.sub(r"\s+", " ", cells[2].split("<details>", 1)[0]).strip())
    return said


@pytest.fixture
def trail(installation):
    """A few days of entries from several parts of the product."""
    root = installation
    _write_day(root, "2026-01-05", [
        _row("external_agent_enrolled", "2026-01-05", 1, external_agent="helpdesk", platform="copilot", enrolled_by="user:alice@example.com"),
        _row("external_action_screened", "2026-01-05", 2, external_agent="helpdesk", tool="send_email", allowed=False, rule="risk_ceiling", reason="Too risky."),
    ])
    _write_day(root, "2026-01-06", [
        _row("approval_decision", "2026-01-06", 1, writer="dashboard", approval_id=7, status="approved", decided_by="user:bob@example.com"),
        _row("agent_drift_detected", "2026-01-06", 2, writer="agent_drift", external_agent="billing", finding="new_tool:x", finding_kind="new_tool", severity="high"),
        _row("agent_watch_synced", "2026-01-06", 3, writer="agent_watch", platforms=1, succeeded=1, failed=0, listed=4, matched=3, not_enrolled=1, missing=0),
    ])
    _write_day(root, "2026-01-07", [
        _row("halt", "2026-01-07", 1, writer="dashboard", actor="user:carol@example.com", operation="halt", source="dashboard"),
        _row("ekko_session", "2026-01-07", 2, writer="dashboard", session_id="s1", state="running"),
        _row("webhook_subscription_changed", "2026-01-07", 3, writer="dashboard", action="update", actor="user:alice@example.com"),
        _row("access_grant_changed", "2026-01-07", 4, writer="dashboard", actor="user:alice@example.com"),
    ])
    return root


# --------------------------------------------------------------------- access

@pytest.mark.parametrize("role", ROLES)
def test_only_those_who_may_read_the_trail_can_open_it_or_its_export(person, trail, role):
    client = person(role)
    before = _log_rows(trail)
    page = client.get("/audit")
    check = client.get("/audit/integrity")
    export = client.post("/audit/export", data={"format": "csv"})
    allowed = role in MAY_READ
    assert page.status_code == (200 if allowed else 403)
    assert check.status_code == (200 if allowed else 403)
    assert export.status_code == (200 if allowed else 403)
    if not allowed:
        assert "helpdesk" not in page.text + check.text + export.text
        assert _log_rows(trail) == before  # a refused export is not recorded either


def test_the_sidebar_offers_the_audit_trail_only_to_those_who_may_read_it(person):
    for role in ROLES:
        html = person(role).get("/").text
        assert ('href="/audit"' in html) == (role in MAY_READ), role


def test_an_auditor_has_this_page_and_the_read_only_pages_and_can_change_nothing(person, trail):
    auditor = person("auditor")
    for path in ("/", "/audit", "/external-agents", "/agent-control-plane"):
        assert auditor.get(path).status_code == 200, path
    assert auditor.get("/approvals").status_code == 403
    before = _log_rows(trail)
    changes = [
        ("/api/v1/external-agents", {"id": "second", "platform": "copilot", "owner": "ops@example.com"}),
        ("/api/v1/external-agents/helpdesk/release", {}),
        ("/api/v1/external-agents/helpdesk/reset-budget", {}),
        ("/api/v1/external-agents/helpdesk/drift/baseline", {"force": True}),
        ("/api/v1/external-agents/helpdesk/drift/check", {}),
        ("/api/v1/agent-control-plane/principals/suspend", {"principal": "agent:helpdesk", "reason": "x"}),
        ("/api/v1/agent-watch/sync", {}),
        ("/api/v1/alerts/test", {}),
        ("/api/v1/approvals/1/approve", {"acknowledged": True}),
    ]
    for path, body in changes:
        assert auditor.post(path, json=body).status_code in {403, 404}, path
    # the refusals are themselves recorded; nothing else is
    assert _log_rows(trail)[:len(before)] == before
    assert {row["kind"] for row in _log_rows(trail)[len(before):]} <= {"capability_denied"}


def test_the_only_thing_the_audit_routes_can_change_is_the_record_of_an_export(app):
    from maverick_dashboard.app import templates
    from maverick_dashboard.audit_page import create_audit_page_router

    methods = {}
    for route in create_audit_page_router(templates).routes:
        path = getattr(route, "path", "")
        if path == "/audit" or path.startswith("/audit/"):
            methods[path] = set(route.methods) - {"HEAD"}
    assert methods == {"/audit": {"GET"}, "/audit/integrity": {"GET"}, "/audit/export": {"POST"}}


def test_a_person_who_is_not_signed_in_gets_nothing(app, trail):
    anonymous = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    assert anonymous.get("/audit").status_code in {302, 303, 401, 403}
    assert anonymous.post("/audit/export", data={"format": "csv"}).status_code in {302, 303, 401, 403}


# -------------------------------------------------------------------- listing

def test_entries_are_listed_newest_first_in_plain_words(person, trail):
    html = person("auditor").get("/audit").text
    said = _lines(html)
    assert said[0] == "alice@example.com changed who can do what."
    assert any("alice@example.com added helpdesk (copilot)" in line for line in said)
    assert any("helpdesk was refused send_email: Too risky." in line for line in said)
    assert any("bob@example.com approved request 7." in line for line in said)
    assert any("Drift was found for billing (new_tool, high severity)." in line for line in said)
    assert any("Platforms were checked: 4 agents found, 1 not added here, 0 checks failed." in line for line in said)
    assert any("The emergency stop was halt" in line for line in said)
    # newest first across days
    position = {word: next(i for i, line in enumerate(said) if word in line) for word in ("approved request 7", "added helpdesk")}
    assert position["approved request 7"] < position["added helpdesk"]


def test_the_raw_fields_are_there_on_demand_and_are_what_the_log_holds(person, trail):
    html = person("auditor").get("/audit").text
    assert "<details>" in html and "Raw fields" in html
    raw = re.search(r"<pre[^>]*>(.*?)</pre>", html.split("approved request 7", 1)[1], re.S).group(1)
    shown = json.loads(raw.replace("&#34;", '"'))
    stored = next(r for r in _log_rows(trail) if r["kind"] == "approval_decision")
    assert shown == stored  # nothing added, nothing taken away


def test_every_kind_of_event_is_in_a_named_group(person, trail):
    from maverick_dashboard import audit_page

    for kind, group in {
        "approval_decision": "approvals", "external_run_ingested": "agents", "agent_trust_changed": "agents",
        "agent_drift_acknowledged": "drift", "agent_baseline_approved": "drift", "agent_watch_synced": "platforms",
        "access_grant_changed": "signin", "webhook_subscription_changed": "settings", "halt": "stop",
        "ekko_erase": "ekko", "audit_exported": "audit", "something_new": "other",
    }.items():
        assert audit_page.group_of({"kind": kind}) == group, kind
    assert audit_page.group_of({"kind": "control_plane_action", "verb": "halt"}) == "stop"
    assert audit_page.group_of({"kind": "control_plane_action", "verb": "suspend"}) == "agents"
    labels = [label for _, label in audit_page.GROUPS]
    assert {"Approvals", "Outside agents", "Drift", "Platform checks", "Sign-in and roles", "Settings",
            "Emergency stop", "Ekko"} <= set(labels)


def test_an_event_this_page_has_no_words_for_is_still_listed(person, installation):
    _write_day(installation, "2026-01-05", [_row("some_new_event", "2026-01-05", 1, writer="dashboard", actor="user:dana@example.com")])
    html = person("auditor").get("/audit").text
    assert "Some new event by dana@example.com." in html and "Other" in html


def test_names_and_reasons_in_the_log_are_escaped(person, installation):
    _write_day(installation, "2026-01-05", [
        _row("external_action_screened", "2026-01-05", 1, external_agent="<img src=x onerror=alert(1)>", tool="<b>tool</b>",
             allowed=False, reason="<script>alert(2)</script>"),
        _row("agent_trust_changed", "2026-01-05", 2, writer="agent_trust", action="added", trusted_agent="<i>x</i>", actor="user:<u>me</u>"),
    ])
    html = person("auditor").get("/audit").text
    for raw in ("<img src=x", "<script>alert(2)", "<b>tool</b>", "<i>x</i>", "<u>me</u>"):
        assert raw not in html, raw
    assert "&lt;img src=x onerror=alert(1)&gt;" in html and "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    # the export neutralises spreadsheet formulas
    _write_day(installation, "2026-01-06", [_row("external_agent_enrolled", "2026-01-06", 1, external_agent="=HYPERLINK(\"http://x\")", platform="p")])
    exported = person("auditor").post("/audit/export", data={"format": "csv", "start": "2026-01-06", "end": "2026-01-06"}).text
    assert "'=HYPERLINK" in exported and ",=HYPERLINK" not in exported


def test_an_empty_trail_says_so(person, installation):
    html = person("auditor").get("/audit").text
    assert "The audit trail has no entries yet" in html
    assert "No entries match" in html


# -------------------------------------------------------------------- filters

def _said(client, **query) -> list[str]:
    page = client.get("/audit", params=query)
    assert page.status_code == 200, page.text
    return _lines(page.text)


def test_the_date_range_filter(person, trail):
    auditor = person("auditor")
    assert len(_said(auditor)) == 9
    only_day = _said(auditor, start="2026-01-06", end="2026-01-06")
    assert len(only_day) == 3 and only_day[-1] == "bob@example.com approved request 7."
    assert len(_said(auditor, start="2026-01-07")) == 4
    assert len(_said(auditor, end="2026-01-05")) == 2
    assert _said(auditor, start="2026-02-01") == []


def test_the_kind_of_event_filter(person, trail):
    auditor = person("auditor")
    assert _said(auditor, group="approvals") == ["bob@example.com approved request 7."]
    assert len(_said(auditor, group="agents")) == 2
    assert len(_said(auditor, group="drift")) == 1 and len(_said(auditor, group="platforms")) == 1
    assert len(_said(auditor, group="signin")) == 1 and len(_said(auditor, group="settings")) == 1
    assert len(_said(auditor, group="stop")) == 1 and len(_said(auditor, group="ekko")) == 1


def test_the_agent_and_person_filters(person, trail):
    auditor = person("auditor")
    assert len(_said(auditor, agent="helpdesk")) == 2
    assert len(_said(auditor, agent="HELP")) == 2
    assert len(_said(auditor, agent="billing")) == 1
    assert len(_said(auditor, person="alice@example.com")) == 3
    assert len(_said(auditor, person="bob")) == 1
    assert len(_said(auditor, person="alice", group="settings")) == 1
    assert _said(auditor, agent="helpdesk", person="bob") == []


def test_a_filter_that_cannot_be_used_is_refused_in_plain_words(person, trail):
    auditor = person("auditor")
    for query, words in (
        ({"start": "yesterday"}, "start date must look like"),
        ({"end": "2026-13-45"}, "end date must look like"),
        ({"start": "2026-02-01", "end": "2026-01-01"}, "start date is after the end date"),
        ({"group": "everything-else"}, "not one of the choices"),
        ({"page": "x"}, "page must be a number"),
        ({"page": "0"}, "between 1 and"),
        ({"page": "100000"}, "between 1 and"),
    ):
        page = auditor.get("/audit", params=query)
        assert page.status_code == 400, query
        assert words in page.text or words in page.json().get("detail", ""), query


# --------------------------------------------------------------------- paging

def test_entries_come_in_pages_of_a_fixed_size_and_each_is_reachable(person, installation):
    _write_day(installation, "2026-01-05", [_row("external_run_started", "2026-01-05", i % 60, external_agent=f"agent-{i:03d}") for i in range(120)])
    auditor = person("auditor")
    first, second, third = (_said(auditor, page=n) for n in (1, 2, 3))
    assert (len(first), len(second), len(third)) == (50, 50, 20)
    assert not set(first) & set(second) and not set(second) & set(third)
    html = auditor.get("/audit", params={"page": 1}).text
    assert "Older" in html and ">Newer<" not in html
    last = auditor.get("/audit", params={"page": 3}).text
    assert "Older" not in last and "Newer" in last
    assert _said(auditor, page=4) == []


def test_a_read_that_hits_its_bounds_says_older_entries_were_not_searched(person, installation, monkeypatch):
    from maverick_dashboard import audit_page

    _write_day(installation, "2026-01-05", [_row("external_run_started", "2026-01-05", i % 60, external_agent="a") for i in range(30)])
    _write_day(installation, "2026-01-06", [_row("external_run_started", "2026-01-06", i % 60, external_agent="b") for i in range(30)])
    monkeypatch.setattr(audit_page, "SCAN_ROWS", 40)
    html = person("auditor").get("/audit").text
    assert "Older entries not searched" in html
    monkeypatch.setattr(audit_page, "SCAN_ROWS", 20000)
    monkeypatch.setattr(audit_page, "DAY_ROWS", 10)
    assert "Older entries not searched" in person("auditor").get("/audit").text


def test_a_day_that_cannot_be_read_is_named_not_skipped_silently(person, installation):
    _write_day(installation, "2026-01-05", [_row("external_run_started", "2026-01-05", 1, external_agent="a")])
    (installation / "audit" / "2026-01-06.ndjson").write_text("{not json\n" + json.dumps(_row("halt", "2026-01-06")) + "\n", encoding="utf-8")
    html = person("auditor").get("/audit").text
    assert "Some days could not be read" in html and "2026-01-06" in html


def test_when_the_audit_folder_cannot_be_read_nothing_is_shown(person, installation, monkeypatch):
    from maverick_dashboard import audit_page

    (installation / "not-a-folder").write_text("x", encoding="utf-8")
    monkeypatch.setattr(audit_page, "audit_dir", lambda: installation / "not-a-folder")
    page = person("auditor").get("/audit")
    assert page.status_code == 503 and "The audit folder is not a folder." in page.text and "Nothing is shown" in page.text
    exported = person("auditor").post("/audit/export", data={"format": "csv"})
    assert exported.status_code == 503 and "Nothing was exported" in exported.text


def test_loading_the_page_changes_nothing_and_checks_nothing(person, trail, monkeypatch):
    from maverick_dashboard import audit_page

    monkeypatch.setattr(audit_page, "verify", lambda *a, **k: pytest.fail("the check runs only when asked"))
    before = _log_rows(trail)
    for role in MAY_READ:
        assert person(role).get("/audit").status_code == 200
    assert _log_rows(trail) == before
    assert "Not checked yet" in person("auditor").get("/audit").text


# --------------------------------------------------------------------- export

def _export(client, fmt="csv", **fields):
    return client.post("/audit/export", data={"format": fmt, **fields})


def test_a_csv_export_holds_the_filtered_entries_and_is_recorded(person, trail):
    auditor = person("auditor")
    before = len(_log_rows(trail))
    answer = _export(auditor, "csv", group="agents")
    assert answer.status_code == 200
    assert answer.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(r'attachment; filename="second-shift-audit-\d{4}-\d{2}-\d{2}\.csv"', answer.headers["content-disposition"])
    assert answer.headers["cache-control"] == "private, no-store"
    rows = list(csv.reader(io.StringIO(answer.text)))
    assert rows[0] == ["When (UTC)", "Kind of event", "Who", "Agent", "What happened", "Event type", "Raw fields"]
    assert len(rows) == 3
    assert {r[5] for r in rows[1:]} == {"external_agent_enrolled", "external_action_screened"}
    assert all(r[1] == "Outside agents" for r in rows[1:])
    assert json.loads(rows[1][6])["kind"] in {"external_agent_enrolled", "external_action_screened"}
    # newest first
    assert rows[1][0] > rows[2][0]
    # and it wrote exactly one entry, saying who exported what
    after = _log_rows(trail)
    assert len(after) == before + 1
    recorded = after[-1]
    assert recorded["kind"] == "audit_exported" and recorded["actor"] == "user:auditor"
    assert recorded["format"] == "csv" and recorded["entries"] == 2 and recorded["kind_of_event"] == "agents"
    assert recorded["hash"] and recorded["sig"]  # signed like every other entry


def test_a_json_export_holds_the_filtered_entries_and_the_filters(person, trail):
    answer = _export(person("governance_lead"), "json", person="alice", start="2026-01-01", end="2026-01-31")
    assert answer.status_code == 200 and answer.headers["content-type"].startswith("application/json")
    assert answer.headers["content-disposition"].endswith('.json"')
    body = answer.json()
    assert body["filters"] == {"start": "2026-01-01", "end": "2026-01-31", "kind_of_event": "", "agent": "", "person": "alice"}
    assert body["truncated"] is False and len(body["entries"]) == 3
    assert {e["event_type"] for e in body["entries"]} == {"external_agent_enrolled", "webhook_subscription_changed", "access_grant_changed"}
    entry = body["entries"][0]
    assert set(entry) == {"when", "kind_of_event", "who", "agent", "what", "event_type", "raw"}
    assert entry["raw"]["kind"] == entry["event_type"]


def test_the_record_of_an_export_holds_no_names_that_were_typed_into_a_filter(person, trail):
    _export(person("auditor"), "json", agent="helpdesk", person="alice@example.com")
    recorded = _log_rows(trail)[-1]
    assert recorded["filtered_by_agent"] is True and recorded["filtered_by_person"] is True
    assert "helpdesk" not in json.dumps(recorded)
    assert "alice@example.com" not in json.dumps(recorded)


def test_the_export_appears_on_the_page_in_its_own_group(person, trail):
    _export(person("auditor"), "csv")
    said = _said(person("auditor"), group="audit")
    assert said == ["auditor exported 9 audit entries as csv."]


def test_an_export_that_cannot_be_recorded_sends_nothing(person, trail, monkeypatch):
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: False)
    answer = _export(person("auditor"), "csv")
    assert answer.status_code == 503 and "nothing was exported" in answer.text
    assert "helpdesk" not in answer.text


def test_an_export_the_audit_log_refuses_sends_nothing(person, trail, monkeypatch):
    from maverick.audit import AuditRefused

    def refuse(*a, **k):
        raise AuditRefused("signing required")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    answer = _export(person("auditor"), "json")
    assert answer.status_code == 503 and "helpdesk" not in answer.text


def test_an_export_with_a_format_that_is_not_offered_is_refused_and_not_recorded(person, trail):
    before = _log_rows(trail)
    for fmt in ("", "xml", "CSV "):
        assert _export(person("auditor"), fmt).status_code == 400
    assert _log_rows(trail) == before


def test_an_export_is_bounded_and_says_when_it_was_cut(person, trail, monkeypatch):
    from maverick_dashboard import audit_page

    monkeypatch.setattr(audit_page, "EXPORT_MAX", 3)
    body = _export(person("auditor"), "json").json()
    assert len(body["entries"]) == 3 and body["truncated"] is True
    assert _log_rows(trail)[-1]["entries"] == 3


# ------------------------------------------------------------------ integrity

def _write_signed(installation, count: int = 3) -> None:
    from maverick.audit import audit_event

    for index in range(count):
        assert audit_event("external_run_started", agent="external_agents", external_agent=f"a{index}")


def test_the_check_passes_for_an_untouched_signed_trail_and_says_what_that_means(person, installation):
    _write_signed(installation)
    answer = person("auditor").get("/audit/integrity").json()
    assert answer["state"] == "intact" and answer["ok"] is True
    assert answer["days_checked"] == 1 and answer["days_total"] == 1 and answer["problems"] == []
    assert "changed or removed" in answer["meaning"]
    assert answer["meaning"].startswith("Passed.")


def test_the_check_fails_when_an_entry_was_changed_and_names_the_day(person, installation):
    _write_signed(installation)
    day = next((installation / "audit").glob("*.ndjson"))
    lines = day.read_text(encoding="utf-8").splitlines()
    changed = json.loads(lines[1])
    changed["external_agent"] = "someone-else"
    lines[1] = json.dumps(changed)
    day.write_text("\n".join(lines) + "\n", encoding="utf-8")
    answer = person("auditor").get("/audit/integrity").json()
    assert answer["state"] == "broken" and answer["ok"] is False
    assert answer["problems"] and answer["problems"][0]["day"] == day.stem
    assert answer["meaning"].startswith("Failed.")


def test_the_check_fails_when_an_entry_was_removed(person, installation):
    _write_signed(installation, 4)
    day = next((installation / "audit").glob("*.ndjson"))
    lines = day.read_text(encoding="utf-8").splitlines()
    del lines[1]
    day.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert person("auditor").get("/audit/integrity").json()["state"] == "broken"


def test_days_without_signatures_are_not_called_intact(person, trail):
    answer = person("auditor").get("/audit/integrity").json()
    assert answer["state"] == "unsigned" and answer["ok"] is False
    assert answer["meaning"].startswith("Not proven.")


def test_an_empty_trail_is_not_called_intact(person, installation):
    answer = person("auditor").get("/audit/integrity").json()
    assert answer["state"] == "empty" and answer["ok"] is False


def test_a_check_that_cannot_run_is_never_a_pass(person, installation, monkeypatch):
    from maverick.audit import signing

    _write_signed(installation)

    def boom(*a, **k):
        raise RuntimeError("cannot read")

    monkeypatch.setattr(signing, "verify_chain", boom)
    answer = person("auditor").get("/audit/integrity").json()
    assert answer["ok"] is False and answer["state"] == "unreadable"
    assert answer["meaning"].startswith("Could not be checked.")


def test_the_check_is_bounded_to_the_newest_days_asked_for(person, installation):
    for day in ("2026-01-05", "2026-01-06", "2026-01-07"):
        _write_day(installation, day, [_row("halt", day)])
    client = person("auditor")
    assert client.get("/audit/integrity", params={"days": 2}).json()["days_checked"] == 2
    assert client.get("/audit/integrity", params={"days": 2}).json()["days_total"] == 3
    assert client.get("/audit/integrity", params={"days": 0}).status_code == 400
    assert client.get("/audit/integrity", params={"days": 91}).status_code == 400


def test_the_page_offers_the_check_as_a_button_and_not_as_a_result(person, installation):
    html = person("auditor").get("/audit").text
    assert 'id="audit-verify"' in html and "Check that nothing was changed" in html
    assert "Passed" not in html.split("<script", 1)[0]
