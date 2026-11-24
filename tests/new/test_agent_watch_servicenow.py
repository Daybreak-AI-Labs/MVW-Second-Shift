"""The ServiceNow platform check against answers shaped like the documented
ones. Nothing here talks to ServiceNow: every request is answered by a
stand-in."""
from __future__ import annotations

import hashlib
import json
import logging
from contextlib import contextmanager

import httpx
import pytest

from maverick import agent_watch as watch
from maverick import agent_watch_servicenow as sn
from maverick import external_agents as xa

T0 = 20_000 * 86400
HOST = "acme.service-now.com"
OTHER = "acmedev.service-now.com"
#: Shaped like real credentials so the secret checks mean something.
CLIENT = "5f2c1a9e8b7d4c3fa1b2c3d4e5f60718"  # pragma: allowlist secret
SECRET = "Zx8~Q.fake-client-secret_4hT9"  # pragma: allowlist secret
TOKEN = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."  # pragma: allowlist secret
         "eyJhdWQiOiJmYWtlIiwiaXNzIjoiZmFrZSJ9.c2lnbmF0dXJlLW5vdC1yZWFs")  # pragma: allowlist secret

AGENT = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
SECOND = "1b2c3d4e5f60718293a4b5c6d7e8f90a"
TOOL = "7e57c0de7e57c0de7e57c0de7e57c0de"
ROLE = "You are an IT service desk specialist."
STEPS = "1. Verify the caller. 2. Reset the password."

#: The fixed column list the check asks each table for.
_FIELDS = {
    "sn_aia_agent": ("sys_id,name,description,role,agent_type,channel,record_type,parent,condition,"
                     "context_processing_script,sys_updated_on"),
    "sn_aia_agent_config": "sys_id,agent,active,public,run_as_user,advanced_mode,agent_learning",
    "sn_aia_version": "sys_id,target_id,version_name,version_number,state,instructions,condition",
    "sn_aia_agent_tool_m2m": "sys_id,agent,tool,name,sys_updated_on",
}
AGENTS, CONFIGS, VERSIONS, TOOLS = _FIELDS

_KEYS = {"client_id_env": "WATCH_SN_CLIENT", "client_secret_env": "WATCH_SN_SECRET"}
_CREDENTIALS = 'client_id_env = "WATCH_SN_CLIENT"\nclient_secret_env = "WATCH_SN_SECRET"\n'


def _url(table: str, offset: int = 0, host: str = HOST) -> str:
    return (f"https://{host}/api/now/table/{table}?sysparm_query=ORDERBYsys_id"
            f"&sysparm_fields={_FIELDS[table]}&sysparm_display_value=false"
            f"&sysparm_exclude_reference_link=true&sysparm_limit=100&sysparm_offset={offset}")


class ServiceNow:
    """A stand-in for ServiceNow instances: each one's sign-in endpoint, plus
    whatever answers the test puts in ``routes`` (address -> body, or a
    function of the request). A request for anything else fails the test."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.routes: dict[str, object] = {}
        self.unexpected: list[str] = []
        self.sign_in: httpx.Response | None = None

    def answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "POST" and request.url.path == "/oauth_token.do":
            return self.sign_in or httpx.Response(200, json={
                "access_token": TOKEN, "scope": "useraccount", "token_type": "Bearer", "expires_in": 1799})
        route = self.routes.get(str(request.url))
        if route is None:
            self.unexpected.append(f"{request.method} {request.url}")
            return httpx.Response(404, json={"error": {"message": "No Record found"}})
        if callable(route):
            return route(request)
        return route if isinstance(route, httpx.Response) else httpx.Response(200, json=route)

    def table(self, name: str, rows: list[dict], host: str = HOST) -> None:
        """Serve ``rows`` as the Table API does: 100 to a page, then an empty page."""
        for offset in range(0, len(rows) + 100, 100):
            self.routes[_url(name, offset, host)] = {"result": rows[offset:offset + 100]}

    def instance(self, agents=(), configs=(), versions=(), tools=(), host: str = HOST) -> None:
        for name, rows in zip(_FIELDS, (agents, configs, versions, tools), strict=True):
            self.table(name, list(rows), host)

    def sign_ins(self) -> list[dict]:
        return [dict(httpx.QueryParams(request.content.decode("ascii")))
                for request in self.requests if request.method == "POST"]

    def reads(self, table: str | None = None) -> list[httpx.Request]:
        return [request for request in self.requests if request.method != "POST"
                and (table is None or request.url.path.endswith(f"/{table}"))]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    monkeypatch.setenv("WATCH_SN_CLIENT", CLIENT)
    monkeypatch.setenv("WATCH_SN_SECRET", SECRET)
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    monkeypatch.setattr(watch, "_TOKENS", {})
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture
def servicenow(monkeypatch):
    from maverick.tools import _ssrf
    service = ServiceNow()

    @contextmanager
    def client(url, timeout=None):
        with httpx.Client(transport=httpx.MockTransport(service.answer), timeout=timeout) as value:
            yield value

    monkeypatch.setattr(_ssrf, "safe_client", client)
    yield service
    assert service.unexpected == []
    # Read-only: apart from the sign-in, the check only ever sends GET.
    assert {request.method for request in service.reads()} <= {"GET"}
    assert all(request.url.scheme == "https" for request in service.requests)
    assert all(request.url.host.endswith(".service-now.com") for request in service.requests)


def _configure(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config
    config.reset_config_cache()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _watcher(instances=(f"https://{HOST}",), **more) -> sn.ServiceNowWatcher:
    return sn.ServiceNowWatcher({**_KEYS, "instances": list(instances), **more})


# -------------------------------------- records as the Table API returns them

def _agent_row(sys_id: str = AGENT, **changes) -> dict:
    """One ``sn_aia_agent`` record. The Table API sends every value as text,
    and an empty column as ""."""
    return {"sys_id": sys_id, "name": "Password reset helper",
            "description": "Resets passwords for employees.", "role": ROLE, "agent_type": "internal",
            "channel": "nap_and_va", "record_type": "custom", "parent": "", "condition": "",
            "context_processing_script": "", "sys_updated_on": "2026-11-02 09:00:00", **changes}


def _config_row(agent: str = AGENT, **changes) -> dict:
    return {"sys_id": "c0" + agent[2:], "agent": agent, "active": "true", "public": "false",
            "run_as_user": "", "advanced_mode": "false", "agent_learning": "false", **changes}


def _version_row(target: str = AGENT, **changes) -> dict:
    return {"sys_id": "f1" + target[2:], "target_id": target, "version_name": "V1", "version_number": "1",
            "state": "published", "instructions": STEPS, "condition": "", **changes}


def _tool_row(agent: str = AGENT, **changes) -> dict:
    return {"sys_id": "70" + agent[2:], "agent": agent, "tool": TOOL, "name": "Reset password",
            "sys_updated_on": "2026-10-30 08:15:00", **changes}


def _setting_digest(**changes) -> str:
    return watch.fingerprint({"active": True, "run_as_user": None, "public": False,
                              "advanced_mode": False, "agent_learning": False, **changes})


def _version_digest(**changes) -> str:
    return watch.fingerprint({"version_name": "V1", "version_number": "1", "state": "published",
                              "instructions": _sha(STEPS), "condition": None, **changes})


def _tool_digest(**changes) -> str:
    return watch.fingerprint({"tool": TOOL, "name": "Reset password",
                              "sys_updated_on": "2026-10-30 08:15:00", **changes})


def _fingerprint(*, settings=None, versions=None, tools=None, **changes) -> str:
    """The fingerprint of ``_agent_row()`` with one settings record, one
    published version and one tool, worked out the long way."""
    return watch.fingerprint({
        "name": "Password reset helper", "agent_type": "internal", "channel": "nap_and_va",
        "record_type": "custom", "parent": None, "role": _sha(ROLE),
        "description": _sha("Resets passwords for employees."), "condition": None,
        "context_processing_script": None,
        "settings": [_setting_digest()] if settings is None else settings,
        "versions": [_version_digest()] if versions is None else versions,
        "tools": [_tool_digest()] if tools is None else tools, **changes})


def _whole(servicenow: ServiceNow, **tables) -> None:
    """One agent with its settings record, published version and tool."""
    tables = {"agents": [_agent_row()], "configs": [_config_row()], "versions": [_version_row()],
              "tools": [_tool_row()], **tables}
    servicenow.instance(**tables)


# ------------------------------------------------------------------- reading

def test_lists_each_agent_with_its_settings_version_and_tools(servicenow):
    _whole(servicenow)
    agent, = _watcher().list_agents()
    assert agent == watch.ObservedAgent(
        platform="servicenow", external_id=f"{HOST}/{AGENT}", name="Password reset helper",
        version="V1", updated_at="2026-11-02 09:00:00", state="enabled",
        fingerprint=_fingerprint(), binding_strength="observed_snapshot")


def test_sends_the_documented_table_api_requests(servicenow):
    _whole(servicenow)
    _watcher().list_agents()
    # Each table is read until a page comes back empty.
    assert [str(read.url) for read in servicenow.reads()] == [
        _url(table, offset) for table in _FIELDS for offset in (0, 100)]
    assert all(read.headers["authorization"] == f"Bearer {TOKEN}" for read in servicenow.reads())
    assert all(read.headers["accept"] == "application/json" for read in servicenow.reads())


def test_signs_in_to_the_instance_with_client_credentials(servicenow):
    servicenow.instance()
    assert _watcher().list_agents() == []
    assert servicenow.sign_ins() == [{"grant_type": "client_credentials", "client_id": CLIENT,
                                      "client_secret": SECRET, "scope": ""}]
    assert str(servicenow.requests[0].url) == f"https://{HOST}/oauth_token.do"
    # An empty table ends at its first page.
    assert len(servicenow.reads()) == 4


def test_a_scope_from_the_settings_is_asked_for(servicenow):
    servicenow.instance()
    _watcher(scope="useraccount table_read").list_agents()
    assert servicenow.sign_ins()[0]["scope"] == "useraccount table_read"


def test_never_keeps_the_role_the_description_or_the_instructions(servicenow):
    _whole(servicenow)
    agent, = _watcher().list_agents()
    for text in ("service desk", "Resets passwords", "Verify the caller"):
        assert text not in repr(agent)


def test_everything_but_the_sys_id_is_optional(servicenow):
    servicenow.instance(agents=[{"sys_id": AGENT.upper()}])
    agent, = _watcher().list_agents()
    # Ids are lower-cased so a reference typed either way matches.
    assert agent.external_id == f"{HOST}/{AGENT}"
    assert (agent.name, agent.state, agent.version, agent.updated_at) == ("", "", "", "")
    assert agent.fingerprint == watch.fingerprint({
        "name": None, "agent_type": None, "channel": None, "record_type": None, "parent": None,
        "role": None, "description": None, "condition": None, "context_processing_script": None,
        "settings": [], "versions": [], "tools": []})


def test_an_absent_column_and_an_empty_one_read_the_same(servicenow):
    servicenow.instance(agents=[{"sys_id": AGENT, "name": "", "role": None, "parent": ""}],
                        configs=[{"sys_id": SECOND, "agent": AGENT}])
    agent, = _watcher().list_agents()
    assert agent.state == ""
    assert agent.fingerprint == watch.fingerprint({
        "name": None, "agent_type": None, "channel": None, "record_type": None, "parent": None,
        "role": None, "description": None, "condition": None, "context_processing_script": None,
        "settings": [_setting_digest(active=None, public=None, advanced_mode=None, agent_learning=None)],
        "versions": [], "tools": []})


def test_records_that_name_no_listed_agent_are_passed_over(servicenow):
    _whole(servicenow, configs=[_config_row(), _config_row(agent=SECOND), _config_row(agent="")],
           versions=[_version_row(), _version_row(target=SECOND, instructions="Something else.")],
           tools=[_tool_row(), _tool_row(agent=SECOND), {"sys_id": SECOND}])
    agent, = _watcher().list_agents()
    assert agent.fingerprint == _fingerprint()


@pytest.mark.parametrize("configs, state", [
    ([_config_row(active="true")], "enabled"),
    ([_config_row(active="false")], "disabled"),
    ([_config_row(active="")], ""),
    ([], ""),
    ([_config_row(active="true"), _config_row(active="true", sys_id=SECOND)], "enabled"),
    ([_config_row(active="true"), _config_row(active="false", sys_id=SECOND)], ""),
])
def test_state_follows_the_active_flag_of_the_settings_record(servicenow, configs, state):
    _whole(servicenow, configs=configs)
    assert _watcher().list_agents()[0].state == state


@pytest.mark.parametrize("versions, label", [
    ([_version_row()], "V1"),
    ([_version_row(version_name="")], "1"),
    ([_version_row(state=" Published ")], "V1"),
    ([_version_row(state="withdrawn")], ""),
    ([_version_row(state="draft")], ""),
    ([], ""),
    ([_version_row(), _version_row(version_name="V2", version_number="2", sys_id=SECOND)], ""),
    ([_version_row(state="withdrawn"),
      _version_row(version_name="V2", version_number="2", sys_id=SECOND)], "V2"),
])
def test_version_is_the_one_published_version(servicenow, versions, label):
    _whole(servicenow, versions=versions)
    assert _watcher().list_agents()[0].version == label


_DRAFT = _version_row(version_name="V2", version_number="2", state="draft", sys_id=SECOND,
                      instructions="1. Reset the password without asking.")


@pytest.mark.parametrize("change, differs", [
    ({"agents": [_agent_row(name="Renamed")]}, True),
    ({"agents": [_agent_row(role="You approve refunds.")]}, True),
    ({"agents": [_agent_row(description="Resets passwords for anyone.")]}, True),
    ({"agents": [_agent_row(agent_type="external")]}, True),
    ({"agents": [_agent_row(channel="nap")]}, True),
    ({"agents": [_agent_row(record_type="template")]}, True),
    ({"agents": [_agent_row(parent=SECOND)]}, True),
    ({"agents": [_agent_row(condition="active=true")]}, True),
    ({"agents": [_agent_row(context_processing_script="return context;")]}, True),
    ({"configs": [_config_row(active="false")]}, True),
    ({"configs": [_config_row(public="true")]}, True),
    ({"configs": [_config_row(run_as_user=SECOND)]}, True),
    ({"configs": [_config_row(advanced_mode="true")]}, True),
    ({"configs": [_config_row(agent_learning="true")]}, True),
    ({"configs": []}, True),
    ({"versions": [_version_row(instructions=STEPS + " 3. Email the new password.")]}, True),
    ({"versions": [_version_row(state="withdrawn")]}, True),
    ({"versions": [_version_row(version_number="2")]}, True),
    ({"versions": [_version_row(condition="priority=1")]}, True),
    ({"versions": [_version_row(), {**_DRAFT, "state": "published"}]}, True),
    ({"tools": []}, True),
    ({"tools": [_tool_row(), _tool_row(tool=SECOND, name="Unlock account", sys_id=SECOND)]}, True),
    ({"tools": [_tool_row(sys_updated_on="2026-11-20 10:00:00")]}, True),
    # A draft is not what runs: adding or editing one changes nothing.
    ({"versions": [_version_row(), _DRAFT]}, False),
    ({"versions": [_version_row(), {**_DRAFT, "instructions": "Edited again."}]}, False),
    # The record's own "updated" time is shown but not fingerprinted.
    ({"agents": [_agent_row(sys_updated_on="2026-11-21 10:00:00")]}, False),
    ({"agents": [_agent_row(sys_mod_count="9", something_new="added later")]}, False),
    ({"configs": [_config_row(sys_id=SECOND)]}, False),
])
def test_fingerprint_follows_what_defines_the_agent(servicenow, change, differs):
    _whole(servicenow)
    before = _watcher().list_agents()[0].fingerprint
    assert before == _fingerprint()
    _whole(servicenow, **change)
    assert (_watcher().list_agents()[0].fingerprint != before) is differs


def test_the_order_records_arrive_in_does_not_matter(servicenow):
    extra = _tool_row(tool=SECOND, name="Unlock account", sys_id=SECOND)
    _whole(servicenow, tools=[_tool_row(), extra])
    before = _watcher().list_agents()[0].fingerprint
    _whole(servicenow, tools=[extra, _tool_row()])
    assert _watcher().list_agents()[0].fingerprint == before


# -------------------------------------------------------------------- paging

def _many(count: int) -> list[dict]:
    return [_agent_row(f"{number:032x}", name=f"Agent {number}") for number in range(1, count + 1)]


def test_pages_by_offset_until_an_empty_page(servicenow):
    servicenow.instance(agents=_many(150))
    agents = _watcher().list_agents()
    assert [agent.name for agent in agents] == [f"Agent {number}" for number in range(1, 151)]
    assert [str(read.url) for read in servicenow.reads(AGENTS)] == [
        _url(AGENTS, 0), _url(AGENTS, 100), _url(AGENTS, 200)]
    assert len(servicenow.sign_ins()) == 1


def test_a_short_page_is_not_the_end_of_the_list(servicenow):
    # ServiceNow applies the page size before its access rules, so a page can
    # come back short, or nearly empty, with more records still to come.
    rows = _many(5)
    servicenow.instance()
    servicenow.routes[_url(AGENTS, 0)] = {"result": rows[:3]}
    servicenow.routes[_url(AGENTS, 100)] = {"result": rows[3:]}
    servicenow.routes[_url(AGENTS, 200)] = {"result": []}
    assert len(_watcher().list_agents()) == 5


def test_a_page_that_repeats_is_an_error(servicenow):
    servicenow.instance()
    servicenow.routes[_url(AGENTS, 0)] = {"result": _many(3)}
    servicenow.routes[_url(AGENTS, 100)] = {"result": _many(3)}
    with pytest.raises(watch.WatchError, match="repeat") as stopped:
        _watcher().list_agents()
    assert HOST in str(stopped.value) and len(servicenow.reads()) == 2


def _endless(request: httpx.Request) -> httpx.Response:
    offset = int(request.url.params["sysparm_offset"])
    return httpx.Response(200, json={"result": [_agent_row(f"{offset + 1:032x}")]})


def test_stops_at_the_page_cap(servicenow, tmp_path):
    _configure(tmp_path, "[agent_watch]\nmax_pages = 3\n")
    for offset in range(0, 600, 100):
        servicenow.routes[_url(AGENTS, offset)] = _endless
    with pytest.raises(watch.WatchError, match="3 pages"):
        _watcher().list_agents()
    assert len(servicenow.reads()) == 3


def test_stops_at_the_record_cap(servicenow, tmp_path):
    _configure(tmp_path, "[agent_watch]\nmax_agents = 2\n")
    servicenow.instance(agents=_many(3))
    with pytest.raises(watch.WatchError, match="more than 2"):
        _watcher().list_agents()


def test_the_record_cap_counts_every_record_read(servicenow, tmp_path):
    _configure(tmp_path, "[agent_watch]\nmax_agents = 3\n")
    _whole(servicenow)
    with pytest.raises(watch.WatchError, match="more than 3") as stopped:
        _watcher().list_agents()
    assert TOOLS in str(stopped.value)


# --------------------------------------------------- answers it cannot use

@pytest.mark.parametrize("table, row", [
    (AGENTS, {}),
    (AGENTS, {"sys_id": None}),
    (AGENTS, {"sys_id": "not-a-sys-id"}),
    (AGENTS, {"sys_id": 7}),
    (AGENTS, _agent_row(name=["a"])),
    (AGENTS, _agent_row(role=7)),
    (AGENTS, _agent_row(parent="somewhere")),
    (AGENTS, _agent_row(parent={"link": f"https://{HOST}/api/now/table/sn_aia_agent/{SECOND}",
                                "value": SECOND})),
    (AGENTS, _agent_row(sys_updated_on="yesterday at noon " * 5)),
    (CONFIGS, _config_row(active="maybe")),
    (CONFIGS, _config_row(active=True)),
    (CONFIGS, _config_row(agent="the first one")),
    (CONFIGS, _config_row(run_as_user={"value": SECOND})),
    (CONFIGS, _config_row(sys_id=None)),
    (VERSIONS, _version_row(instructions=["step one"])),
    (VERSIONS, _version_row(target_id=5)),
    (VERSIONS, _version_row(state=3)),
    (TOOLS, _tool_row(tool="reset-password")),
    (TOOLS, _tool_row(sys_updated_on=20261030)),
    (TOOLS, _tool_row(sys_id={"x": 1})),
])
def test_refuses_a_record_it_cannot_understand(servicenow, table, row):
    names = {AGENTS: "agents", CONFIGS: "configs", VERSIONS: "versions", TOOLS: "tools"}
    good = {AGENTS: _agent_row(SECOND), CONFIGS: _config_row(SECOND), VERSIONS: _version_row(SECOND),
            TOOLS: _tool_row(SECOND)}[table]
    _whole(servicenow, **{names[table]: [good, row]})
    with pytest.raises(watch.WatchError) as refused:
        _watcher().list_agents()
    text = str(refused.value)
    assert "expected form" in text and HOST in text and table in text


@pytest.mark.parametrize("page", [
    {"result": "none"}, {"result": [["sys_id", AGENT]]}, {"records": []},
    httpx.Response(200, content=b"[]"), httpx.Response(200, content=b"<html>Instance hibernating</html>"),
])
def test_refuses_a_page_it_cannot_understand(servicenow, page):
    servicenow.routes[_url(AGENTS)] = page
    with pytest.raises(watch.WatchError, match="expected form") as refused:
        _watcher().list_agents()
    assert "hibernating" not in str(refused.value)


def test_says_when_the_role_has_not_been_granted(servicenow):
    servicenow.routes[_url(AGENTS)] = httpx.Response(403, json={"error": {
        "message": "User Not Authorized", "detail": f"ACL failed for token {TOKEN}"}, "status": "failure"})
    with pytest.raises(watch.WatchError) as refused:
        _watcher().list_agents()
    text = str(refused.value)
    assert "permission" in text and AGENTS in text and TOKEN not in text and "ACL failed" not in text


def test_says_when_the_sign_in_is_refused(servicenow):
    servicenow.sign_in = httpx.Response(401, json={
        "error": "invalid_client", "error_description": f"client secret {SECRET} is not valid"})
    with pytest.raises(watch.WatchError) as refused:
        _watcher().list_agents()
    text = str(refused.value)
    assert "invalid_client" in text and HOST in text and SECRET not in text
    assert servicenow.reads() == []


@pytest.mark.parametrize("variable, setting", [("WATCH_SN_CLIENT", "client_id_env"),
                                               ("WATCH_SN_SECRET", "client_secret_env")])
def test_a_credential_that_is_not_set_is_named_by_its_setting(servicenow, monkeypatch, variable, setting):
    monkeypatch.delenv(variable)
    with pytest.raises(watch.WatchError) as missing:
        _watcher().list_agents()
    assert f"{setting} in [agent_watch.servicenow] is not set" in str(missing.value)
    assert servicenow.requests == []


# ------------------------------------------------------------ two instances

def test_reads_every_instance_and_keeps_the_same_sys_id_apart(servicenow):
    _whole(servicenow)
    _whole(servicenow, host=OTHER, versions=[_version_row(instructions="Still being tried out.")])
    agents = _watcher([f"https://{HOST}", f"https://{OTHER}/"]).list_agents()
    assert [agent.external_id for agent in agents] == [f"{HOST}/{AGENT}", f"{OTHER}/{AGENT}"]
    assert agents[0].fingerprint != agents[1].fingerprint
    # Each instance is its own sign-in service.
    assert [str(request.url) for request in servicenow.requests if request.method == "POST"] == [
        f"https://{HOST}/oauth_token.do", f"https://{OTHER}/oauth_token.do"]


def test_one_instance_failing_fails_the_run_and_says_which(servicenow):
    _whole(servicenow)
    _whole(servicenow, host=OTHER)
    servicenow.routes[_url(VERSIONS, 0, OTHER)] = httpx.Response(403, json={"error": {
        "message": "User Not Authorized", "detail": "Required to provide Auth information"}})
    with pytest.raises(watch.WatchError) as refused:
        _watcher([f"https://{HOST}", f"https://{OTHER}"]).list_agents()
    text = str(refused.value)
    assert f"{OTHER}, table {VERSIONS}" in text and "HTTP 403" in text and "Auth information" not in text


# ------------------------------------------------------------------ settings

@pytest.mark.parametrize("instances", [
    None, f"https://{HOST}", [], [7], [f"http://{HOST}"], [HOST],
    ["https://acme.service-now.com.evil.example"], ["https://evil.example"],
    ["https://service-now.com"], ["https://acme.servicenow.com"], ["https://support.acme.example"],
    [f"https://user:pw@{HOST}"], [f"https://{HOST}/api/now/table/sn_aia_agent"],
    [f"https://{HOST}/oauth_token.do"], [f"https://{HOST}?sysparm_query=x"], [f"https://{HOST}:8443"],
    ["https://acme.evil.example/.service-now.com"], ["https://a.b.service-now.com"],
    [f"https://{HOST}", f"https://{HOST.upper()}/"],
    [f"https://org{number}.service-now.com" for number in range(21)],
])
def test_instances_must_be_instance_addresses_and_are_never_echoed(instances):
    settings = dict(_KEYS) if instances is None else {**_KEYS, "instances": instances}
    with pytest.raises(watch.WatchConfigError) as refused:
        sn.ServiceNowWatcher(settings)
    text = str(refused.value)
    assert "instances" in text and "[agent_watch.servicenow]" in text
    assert "evil.example" not in text and "user:pw" not in text and "acme" not in text


def test_instance_host_case_does_not_matter():
    watcher = _watcher(["https://ACME.Service-Now.com/"])
    assert watcher._instances == [HOST]


@pytest.mark.parametrize("settings, words", [
    ({}, "client_id_env"),
    ({**_KEYS, "client_id_env": CLIENT + " "}, "client_id_env"),
    ({**_KEYS, "client_id_env": 7}, "client_id_env"),
    ({**_KEYS, "client_secret_env": SECRET}, "client_secret_env"),
    ({**_KEYS, "client_secret": SECRET}, "client_secret_env"),
    ({**_KEYS, "token_url": "https://evil.example/oauth_token.do"}, "token_url"),
    ({**_KEYS, "table": "sys_user"}, "table"),
    ({**_KEYS, SECRET: "x"}, "does not know"),
    ({**_KEYS, "scope": 7}, "scope"),
    ({**_KEYS, "scope": "useraccount&client_id=other"}, "scope"),
    ({**_KEYS, "scope": "two  spaces"}, "scope"),
    ({**_KEYS, "scope": SECRET}, "scope"),
])
def test_settings_are_checked_and_never_echoed(settings, words):
    with pytest.raises(watch.WatchConfigError) as refused:
        sn.ServiceNowWatcher({"instances": [f"https://{HOST}"], **settings})
    text = str(refused.value)
    assert words in text and "[agent_watch.servicenow]" in text
    assert SECRET not in text and CLIENT not in text and "evil.example" not in text


# ------------------------------------------------- through the whole check

_WATCHING = ('[agent_watch]\nenable = true\nplatforms = ["servicenow"]\n'
             f'[agent_watch.servicenow]\n{_CREDENTIALS}instances = ["https://{HOST}"]\n')


def _enroll(agent_id: str, ref: str) -> None:
    xa.enroll(agent_id, "custom", owner="jordan@corp.test", enrolled_by="admin@corp.test")
    path = xa.registry_path()
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[agent_id]["external_ref"] = ref
    path.write_text(json.dumps(entries), encoding="utf-8")


class _Steady:
    """Another platform, which always answers with one agent."""

    name = "other"

    def list_agents(self) -> list[watch.ObservedAgent]:
        return [watch.ObservedAgent(platform="other", external_id="bot-1", name="Bot",
                                    fingerprint=watch.fingerprint({"config": "v1"}))]


def test_the_servicenow_check_is_registered_out_of_the_box():
    assert "agent_watch_servicenow" in watch._WATCHER_MODULES
    assert "servicenow" in watch.registered()


def test_a_check_matches_enrolled_agents_and_lists_the_rest(servicenow, tmp_path, caplog):
    from maverick import agent_drift
    _configure(tmp_path, _WATCHING)
    # The reference is matched whatever case it was typed in.
    _enroll("reset-helper", f"servicenow:{HOST}/{AGENT.upper()}")
    _whole(servicenow, agents=[_agent_row(), _agent_row(SECOND, name="Unclaimed agent")])
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    row = summary["platforms"]["servicenow"]
    assert (row["ok"], row["listed"], row["matched"], row["not_enrolled"]) == (True, 2, 1, 1)
    unclaimed, = watch.unenrolled()
    assert (unclaimed["external_ref"], unclaimed["name"]) == (f"servicenow:{HOST}/{SECOND}",
                                                             "Unclaimed agent")
    view = watch.platform_view("reset-helper")
    assert (view["listed"], view["state"], view["version"], view["updated_at"]) == (
        True, "enabled", "V1", "2026-11-02 09:00:00")
    seen = agent_drift.detail("reset-helper", now=T0)["config"]["discovered"]
    assert seen == {"version_digest": _fingerprint(), "seen_at": T0, "source": "servicenow",
                    "binding_strength": "observed_snapshot"}
    assert all(platform["ready"] for platform in watch.status()["platforms"])

    everything = (json.dumps(summary) + json.dumps(watch.status()) + json.dumps(watch.unenrolled())
                  + caplog.text + watch.store_path().read_text(encoding="utf-8")
                  + agent_drift.store_path().read_text(encoding="utf-8"))
    for hidden in (SECRET, TOKEN, CLIENT, "service desk", "Verify the caller", "Resets passwords"):
        assert hidden not in everything


def test_changed_instructions_become_a_drift_finding(servicenow, tmp_path):
    from maverick import agent_drift
    _configure(tmp_path, _WATCHING)
    _enroll("reset-helper", f"servicenow:{HOST}/{AGENT}")
    _whole(servicenow)
    watch.sync(now=T0)
    agent_drift.approve_baseline("reset-helper", actor="dana@corp.test", force=True, now=T0 + 60)
    assert [f for f in agent_drift.evaluate("reset-helper", now=T0 + 120)["findings"]
            if f["kind"] == "config_changed"] == []
    _whole(servicenow, versions=[_version_row(instructions="1. Reset any password that is asked for.")])
    watch.sync(now=T0 + 3600)
    finding, = [f for f in agent_drift.evaluate("reset-helper", now=T0 + 3700)["findings"]
                if f["kind"] == "config_changed"]
    assert (finding["severity"], finding["source"]) == ("high", "discovery")


def test_servicenow_failing_does_not_stop_another_platform(servicenow, tmp_path, monkeypatch):
    monkeypatch.setitem(watch._FACTORIES, "other", lambda settings: _Steady())
    _configure(tmp_path, _WATCHING.replace('["servicenow"]', '["servicenow", "other"]'))
    _enroll("reset-helper", f"servicenow:{HOST}/{AGENT}")
    _whole(servicenow)
    assert watch.sync(now=T0)["succeeded"] == 2
    servicenow.routes[_url(CONFIGS)] = httpx.Response(500, content=b"Internal Server Error")
    summary = watch.sync(now=T0 + 3600)
    assert {name: row["ok"] for name, row in summary["platforms"].items()} == {
        "servicenow": False, "other": True}
    assert "HTTP 500" in summary["platforms"]["servicenow"]["error"]
    # What was known about the failed platform is kept as it was.
    view = watch.platform_view("reset-helper")
    assert (view["listed"], view["last_seen_at"], view["missing_runs"]) == (True, T0, 0)
    failed = next(row for row in watch.status()["platforms"] if row["name"] == "servicenow")
    assert (failed["last_success_at"], failed["failures_in_a_row"], failed["listed"]) == (T0, 1, 1)


def test_secrets_stay_out_of_everything_when_the_check_fails(servicenow, tmp_path, caplog):
    _configure(tmp_path, _WATCHING)
    servicenow.routes[_url(AGENTS)] = httpx.Response(401, json={"error": {
        "message": "User Not Authenticated", "detail": f"bad token {TOKEN} for client {CLIENT}"}})
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    servicenow.routes[_url(AGENTS)] = httpx.Response(200, content=f'{{"result": "{SECRET}"'.encode())
    with caplog.at_level(logging.DEBUG):
        again = watch.sync(now=T0 + 60)
    assert summary["platforms"]["servicenow"]["ok"] is False and again["platforms"]["servicenow"]["ok"] is False
    everything = (json.dumps(summary) + json.dumps(again) + json.dumps(watch.status()) + caplog.text
                  + watch.store_path().read_text(encoding="utf-8"))
    for hidden in (SECRET, TOKEN, CLIENT):
        assert hidden not in everything
    assert "sign-in" in summary["platforms"]["servicenow"]["error"]
    assert HOST in again["platforms"]["servicenow"]["error"]


def test_malformed_settings_show_in_status_without_their_values(servicenow, tmp_path):
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = ["servicenow"]\n'
                         f'[agent_watch.servicenow]\n{_CREDENTIALS}client_secret = "{SECRET}"\n'
                         'instances = ["https://evil.example"]\n')
    row, = watch.status()["platforms"]
    assert row["ready"] is False and "client_secret_env" in row["problem"]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["servicenow"]["ok"] is False
    everything = (json.dumps(summary) + json.dumps(watch.status())
                  + watch.store_path().read_text(encoding="utf-8"))
    assert SECRET not in everything and "evil.example" not in everything
    # A platform whose settings are refused is never contacted.
    assert servicenow.requests == []


def test_a_check_only_ever_reaches_the_fixed_addresses(servicenow, tmp_path):
    _configure(tmp_path, _WATCHING)
    _whole(servicenow)
    watch.sync(now=T0)
    assert [(request.method, str(request.url)) for request in servicenow.requests] == [
        ("POST", f"https://{HOST}/oauth_token.do"),
        *(("GET", _url(table, offset)) for table in _FIELDS for offset in (0, 100))]
