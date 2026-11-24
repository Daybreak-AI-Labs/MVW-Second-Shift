"""The Microsoft platform checks (Entra Agent ID, Foundry Agent Service,
Copilot Studio) against answers shaped like the documented ones. Nothing here
talks to Microsoft: every request is answered by a stand-in."""
from __future__ import annotations

import hashlib
import json
import logging
from contextlib import contextmanager

import httpx
import pytest

from maverick import agent_watch as watch
from maverick import agent_watch_microsoft as ms
from maverick import external_agents as xa

T0 = 20_000 * 86400
TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
CLIENT = "00001111-aaaa-2222-bbbb-3333cccc4444"
#: Shaped like real credentials so the secret checks mean something.
SECRET = "Zx8~Q.fake-client-secret_4hT9"  # pragma: allowlist secret
TOKEN = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."  # pragma: allowlist secret
         "eyJhdWQiOiJmYWtlIiwiaXNzIjoiZmFrZSJ9.c2lnbmF0dXJlLW5vdC1yZWFs")  # pragma: allowlist secret

LOGIN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
PROJECT = "https://contoso-ai.services.ai.azure.com/api/projects/sales"
FOUNDRY = PROJECT + "/agents?api-version=v1&limit=50&order=asc"
ORG = "contoso.crm4.dynamics.com"
BOTS = (f"https://{ORG}/api/data/v9.2/bots"
        "?$select=botid,name,schemaname,publishedon,modifiedon,statecode,statuscode&$orderby=botid")

_CREDENTIALS = ('tenant_id_env = "WATCH_TENANT"\nclient_id_env = "WATCH_CLIENT"\n'
                'client_secret_env = "WATCH_SECRET"\n')
_KEYS = {"tenant_id_env": "WATCH_TENANT", "client_id_env": "WATCH_CLIENT",
         "client_secret_env": "WATCH_SECRET"}


class Microsoft:
    """A stand-in for the Microsoft services: the sign-in endpoint, plus
    whatever answers the test puts in ``routes`` (address -> body, or a
    function of the request). A request for anything else fails the test."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.routes: dict[str, object] = {}
        self.unexpected: list[str] = []
        self.sign_in: httpx.Response | None = None

    def answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            return self.sign_in or httpx.Response(200, json={
                "token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN})
        route = self.routes.get(str(request.url))
        if route is None:
            self.unexpected.append(f"{request.method} {request.url}")
            return httpx.Response(404, json={"error": {"code": "NotFound"}})
        if callable(route):
            return route(request)
        return route if isinstance(route, httpx.Response) else httpx.Response(200, json=route)

    def sign_ins(self) -> list[dict]:
        return [dict(httpx.QueryParams(request.content.decode("ascii")))
                for request in self.requests if request.method == "POST"]

    def reads(self) -> list[httpx.Request]:
        return [request for request in self.requests if request.method != "POST"]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    monkeypatch.setenv("WATCH_TENANT", TENANT)
    monkeypatch.setenv("WATCH_CLIENT", CLIENT)
    monkeypatch.setenv("WATCH_SECRET", SECRET)
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
def microsoft(monkeypatch):
    from maverick.tools import _ssrf
    service = Microsoft()

    @contextmanager
    def client(url, timeout=None):
        with httpx.Client(transport=httpx.MockTransport(service.answer), timeout=timeout) as value:
            yield value

    monkeypatch.setattr(_ssrf, "safe_client", client)
    yield service
    assert service.unexpected == []
    # Read-only: apart from the sign-in, a check only ever sends GET.
    assert {request.method for request in service.reads()} <= {"GET"}
    assert all(request.url.scheme == "https" for request in service.requests)


def _configure(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config
    config.reset_config_cache()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ------------------------------------------------------------ Entra Agent ID

def _identity(**changes) -> dict:
    """One agentIdentity as the documented list answer shows it."""
    return {"id": "1b7313c4-05d0-4a08-88e3-7b76c003a0a2", "displayName": "My Agent Identity",
            "createdDateTime": "2019-09-17T19:10:35.2742618Z",
            "createdByAppId": "00001111-aaaa-2222-bbbb-3333cccc4444",
            "agentIdentityBlueprintId": "00001111-aaaa-2222-bbbb-3333cccc4444",
            "accountEnabled": True, "disabledByMicrosoftStatus": None,
            "servicePrincipalType": "ServiceIdentity", "tags": [], **changes}


def _entra() -> ms.EntraAgentIdWatcher:
    return ms.EntraAgentIdWatcher(dict(_KEYS))


def test_entra_lists_agent_identities(microsoft):
    microsoft.routes[GRAPH] = {"value": [_identity()]}
    agent, = _entra().list_agents()
    assert agent == watch.ObservedAgent(
        platform="entra_agent_id", external_id="1b7313c4-05d0-4a08-88e3-7b76c003a0a2",
        name="My Agent Identity", version="", updated_at="", state="enabled",
        fingerprint=watch.fingerprint({
            "displayName": "My Agent Identity", "accountEnabled": True,
            "agentIdentityBlueprintId": "00001111-aaaa-2222-bbbb-3333cccc4444",
            "disabledByMicrosoftStatus": None, "servicePrincipalType": "ServiceIdentity"}),
        binding_strength="observed_snapshot")
    read, = microsoft.reads()
    assert str(read.url) == GRAPH and read.headers["authorization"] == f"Bearer {TOKEN}"


def test_entra_signs_in_with_the_tenants_client_credentials_for_graph(microsoft):
    microsoft.routes[GRAPH] = {"value": []}
    assert _entra().list_agents() == []
    sign_in, = microsoft.sign_ins()
    assert sign_in == {"grant_type": "client_credentials", "client_id": CLIENT,
                       "client_secret": SECRET, "scope": "https://graph.microsoft.com/.default"}
    assert str(microsoft.requests[0].url) == LOGIN


def test_entra_follows_next_links_and_signs_in_once(microsoft):
    second = GRAPH + "?$skiptoken=RFNwdAIAAQAAAD8AAAAAAAAA"
    microsoft.routes[GRAPH] = {"value": [_identity()], "@odata.nextLink": second}
    microsoft.routes[second] = {"value": [_identity(id="2C8424D5-16E1-5B19-99F4-8C87D114B1B3",
                                                    displayName="Second")]}
    agents = _entra().list_agents()
    # Ids are lower-cased so a reference typed either way matches.
    assert [agent.external_id for agent in agents] == ["1b7313c4-05d0-4a08-88e3-7b76c003a0a2",
                                                        "2c8424d5-16e1-5b19-99f4-8c87d114b1b3"]
    assert len(microsoft.sign_ins()) == 1 and len(microsoft.reads()) == 2


def test_entra_treats_everything_but_the_id_as_optional(microsoft):
    microsoft.routes[GRAPH] = {"value": [{"id": "1b7313c4-05d0-4a08-88e3-7b76c003a0a2"}]}
    agent, = _entra().list_agents()
    assert (agent.name, agent.state, agent.version, agent.updated_at) == ("", "", "", "")
    assert agent.fingerprint == watch.fingerprint({
        "displayName": None, "accountEnabled": None, "agentIdentityBlueprintId": None,
        "disabledByMicrosoftStatus": None, "servicePrincipalType": None})


def test_entra_state_follows_account_enabled(microsoft):
    microsoft.routes[GRAPH] = {"value": [_identity(accountEnabled=False)]}
    assert _entra().list_agents()[0].state == "disabled"


@pytest.mark.parametrize("change, differs", [
    ({"accountEnabled": False}, True),
    ({"agentIdentityBlueprintId": "99998888-aaaa-2222-bbbb-3333cccc4444"}, True),
    ({"displayName": "Renamed"}, True),
    ({"disabledByMicrosoftStatus": "DisabledDueToViolationOfServicesAgreement"}, True),
    ({"servicePrincipalType": "Application"}, True),
    ({"tags": ["reviewed"]}, False),
    ({"createdDateTime": "2026-01-01T00:00:00Z"}, False),
    ({"somethingNew": {"added": "later"}}, False),
])
def test_entra_fingerprint_follows_what_defines_the_identity(microsoft, change, differs):
    microsoft.routes[GRAPH] = {"value": [_identity()]}
    before = _entra().list_agents()[0].fingerprint
    microsoft.routes[GRAPH] = {"value": [_identity(**change)]}
    assert (_entra().list_agents()[0].fingerprint != before) is differs


@pytest.mark.parametrize("row", [
    {}, {"id": None}, {"id": "not-a-guid"}, {"id": 7},
    _identity(accountEnabled="yes"), _identity(displayName=["a"]),
    _identity(agentIdentityBlueprintId=7), _identity(disabledByMicrosoftStatus={"x": 1}),
])
def test_entra_refuses_a_row_it_cannot_understand(microsoft, row):
    microsoft.routes[GRAPH] = {"value": [_identity(id="2c8424d5-16e1-5b19-99f4-8c87d114b1b3"), row]}
    with pytest.raises(watch.WatchError, match="expected form"):
        _entra().list_agents()


def test_entra_says_when_the_permission_has_not_been_granted(microsoft):
    microsoft.routes[GRAPH] = httpx.Response(403, json={"error": {
        "code": "Authorization_RequestDenied", "message": f"Insufficient privileges {TOKEN}"}})
    with pytest.raises(watch.WatchError) as refused:
        _entra().list_agents()
    assert "permission" in str(refused.value) and TOKEN not in str(refused.value)
    assert "Authorization_RequestDenied" not in str(refused.value)


def test_entra_says_when_the_sign_in_is_refused(microsoft):
    microsoft.sign_in = httpx.Response(401, json={
        "error": "invalid_client", "error_codes": [7000215],
        "error_description": f"AADSTS7000215: Invalid client secret provided {SECRET}"})
    with pytest.raises(watch.WatchError) as refused:
        _entra().list_agents()
    assert "invalid_client" in str(refused.value) and SECRET not in str(refused.value)
    assert microsoft.reads() == []


@pytest.mark.parametrize("variable, setting", [("WATCH_TENANT", "tenant_id_env"),
                                               ("WATCH_CLIENT", "client_id_env"),
                                               ("WATCH_SECRET", "client_secret_env")])
def test_a_credential_that_is_not_set_is_named_by_its_setting(microsoft, monkeypatch, variable, setting):
    monkeypatch.delenv(variable)
    with pytest.raises(watch.WatchError) as missing:
        _entra().list_agents()
    assert f"{setting} in [agent_watch.entra_agent_id] is not set" in str(missing.value)
    assert microsoft.requests == []


@pytest.mark.parametrize("variable, value", [
    ("WATCH_TENANT", "contoso/../common"), ("WATCH_TENANT", "tenant?x=1"),
    ("WATCH_TENANT", "tenant id"), ("WATCH_TENANT", "x" * 300),
    ("WATCH_CLIENT", "client&scope=other"), ("WATCH_CLIENT", "has space")])
def test_a_tenant_or_client_id_that_is_not_one_is_refused_before_any_request(
        microsoft, monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(watch.WatchError) as refused:
        _entra().list_agents()
    assert value not in str(refused.value) and microsoft.requests == []


def test_a_tenant_may_be_given_as_a_domain_name(microsoft, monkeypatch):
    monkeypatch.setenv("WATCH_TENANT", "contoso.onmicrosoft.com")
    microsoft.routes[GRAPH] = {"value": []}
    _entra().list_agents()
    assert str(microsoft.requests[0].url) == \
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"


@pytest.mark.parametrize("settings, words", [
    ({}, "tenant_id_env"),
    ({**_KEYS, "tenant_id_env": TENANT + " "}, "tenant_id_env"),
    ({**_KEYS, "client_id_env": 7}, "client_id_env"),
    ({**_KEYS, "client_secret_env": SECRET}, "client_secret_env"),
    ({**_KEYS, "client_secret": SECRET}, "client_secret_env"),
    ({**_KEYS, "endpoint": "https://graph.microsoft.com/beta"}, "endpoint"),
    ({**_KEYS, SECRET: "x"}, "does not know"),
])
def test_entra_settings_are_checked_and_never_echoed(settings, words):
    with pytest.raises(watch.WatchConfigError) as refused:
        ms.EntraAgentIdWatcher(settings)
    text = str(refused.value)
    assert words in text and "[agent_watch.entra_agent_id]" in text
    assert SECRET not in text and TENANT not in text


# ------------------------------------------------------------------- Foundry

def _foundry_agent(name: str = "quote-agent", *, version: str = "3", state="enabled",
                   definition: dict | None = None, **latest) -> dict:
    """One AgentObject as the documented list answer describes it."""
    if definition is None:
        definition = {"kind": "prompt", "model": "gpt-4.1", "instructions": "You write quotes.",
                      "tools": [{"type": "mcp", "server_label": "crm",
                                 "server_url": "https://crm.example/mcp"},
                                {"type": "code_interpreter"}]}
    agent = {"object": "agent", "id": name, "name": name, "configuration_state": "enabled",
             "versions": {"latest": {"metadata": {}, "object": "agent.version",
                                     "id": f"{name}:{version}", "name": name, "version": version,
                                     "description": "", "created_at": 1762000000,
                                     "definition": definition, "status": "active", **latest}}}
    if state is not None:
        agent["state"] = state
    return agent


def _page(agents: list[dict], *, has_more: bool = False, **extra) -> dict:
    page = {"data": agents, "has_more": has_more, **extra}
    if agents:
        page.setdefault("first_id", agents[0]["id"])
        page.setdefault("last_id", agents[-1]["id"])
    return page


def _foundry(endpoints=(PROJECT,)) -> ms.FoundryWatcher:
    return ms.FoundryWatcher({**_KEYS, "endpoints": list(endpoints)})


def _prompt_fingerprint(*, version="3", model="gpt-4.1", instructions="You write quotes.",
                        tools=None) -> str:
    if tools is None:
        tools = [{"type": "mcp", "server_label": "crm", "server_url": "https://crm.example/mcp"},
                 {"type": "code_interpreter"}]
    return watch.fingerprint({
        "version": version, "kind": "prompt", "model": model,
        "instructions": None if instructions is None else _sha(instructions),
        "tools": sorted(_sha(_canonical(tool)) for tool in tools)})


def test_foundry_lists_each_agent_with_its_latest_version(microsoft):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    agent, = _foundry().list_agents()
    assert agent == watch.ObservedAgent(
        platform="foundry", external_id="contoso-ai/sales/quote-agent", name="quote-agent",
        version="3", updated_at="2025-11-01T12:26:40Z", state="enabled",
        fingerprint=_prompt_fingerprint(), binding_strength="immutable_provider_revision")
    read, = microsoft.reads()
    assert str(read.url) == FOUNDRY and read.headers["authorization"] == f"Bearer {TOKEN}"
    assert microsoft.sign_ins()[0]["scope"] == "https://ai.azure.com/.default"


def test_foundry_never_keeps_the_instructions_or_the_tool_settings(microsoft):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    agent, = _foundry().list_agents()
    assert "You write quotes" not in repr(agent) and "crm.example" not in repr(agent)


@pytest.mark.parametrize("change, differs", [
    ({"version": "4"}, True),
    ({"model": "gpt-4.1-mini"}, True),
    ({"instructions": "You write quotes and send them."}, True),
    ({"instructions": None}, True),
    ({"tools": [{"type": "code_interpreter"}]}, True),
    ({"tools": [{"type": "mcp", "server_label": "crm", "server_url": "https://other.example/mcp"},
                {"type": "code_interpreter"}]}, True),
    # The same tools in another order, or written with their keys in another order.
    ({"tools": [{"type": "code_interpreter"},
                {"server_url": "https://crm.example/mcp", "type": "mcp", "server_label": "crm"}]}, False),
])
def test_foundry_fingerprint_follows_version_model_instructions_and_tools(microsoft, change, differs):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    before = _foundry().list_agents()[0].fingerprint
    version = change.pop("version", "3")
    definition = {**_foundry_agent()["versions"]["latest"]["definition"], **change}
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(version=version, definition=definition)])
    after = _foundry().list_agents()[0].fingerprint
    assert (after != before) is differs
    assert after == _prompt_fingerprint(version=version, **{
        key: definition[key] for key in ("model", "instructions", "tools")})


def test_foundry_fingerprint_ignores_what_is_not_configuration(microsoft):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    before = _foundry().list_agents()[0]
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(
        state="disabled", description="edited", metadata={"owner": "sales"}, status="creating")])
    after = _foundry().list_agents()[0]
    assert after.fingerprint == before.fingerprint and after.state == "disabled"


def test_foundry_treats_undocumented_or_optional_fields_as_optional(microsoft):
    hosted = {"kind": "hosted", "cpu": "1", "memory": "2Gi"}
    bare = _foundry_agent("worker", definition=hosted, state=None)
    del bare["versions"]["latest"]["created_at"]
    microsoft.routes[FOUNDRY] = _page([bare])
    agent, = _foundry().list_agents()
    assert (agent.state, agent.updated_at, agent.version) == ("", "", "3")
    assert agent.binding_strength == "immutable_provider_revision"
    assert agent.fingerprint == watch.fingerprint({
        "version": "3", "kind": "hosted", "model": None, "instructions": None, "tools": []})


def test_foundry_reads_a_state_it_does_not_know_as_unknown(microsoft):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(state="archived")])
    assert _foundry().list_agents()[0].state == ""


def test_foundry_pages_with_the_after_cursor(microsoft):
    second = FOUNDRY + "&after=agent%2Ftwo"
    third = FOUNDRY + "&after=agent-three"
    microsoft.routes[FOUNDRY] = _page([_foundry_agent("one"), _foundry_agent("agent-two")],
                                      has_more=True, last_id="agent/two")
    # No last_id on this page: the last item's own id is the cursor.
    page_two = {"data": [_foundry_agent("agent-three")], "has_more": True}
    microsoft.routes[second] = page_two
    microsoft.routes[third] = _page([_foundry_agent("four")])
    agents = _foundry().list_agents()
    assert [agent.name for agent in agents] == ["one", "agent-two", "agent-three", "four"]
    assert [str(read.url) for read in microsoft.reads()] == [FOUNDRY, second, third]


@pytest.mark.parametrize("page", [
    {"data": [], "has_more": True},                                  # more, but no cursor
    {"data": [_foundry_agent("one")], "has_more": True, "last_id": 7},
    {"data": [_foundry_agent("one")], "has_more": True, "last_id": ""},
    {"data": [_foundry_agent("one")]},                               # has_more is required
    {"data": [_foundry_agent("one")], "has_more": "false"},
    {"data": "none", "has_more": False},
    {"value": [_foundry_agent("one")], "has_more": False},
])
def test_foundry_refuses_a_page_it_cannot_follow(microsoft, page):
    page.pop("first_id", None)
    microsoft.routes[FOUNDRY] = page
    with pytest.raises(watch.WatchError, match="expected form"):
        _foundry().list_agents()


def test_foundry_stops_on_a_cursor_that_repeats(microsoft):
    again = FOUNDRY + "&after=one"
    microsoft.routes[FOUNDRY] = _page([_foundry_agent("one")], has_more=True)
    microsoft.routes[again] = _page([_foundry_agent("one")], has_more=True)
    with pytest.raises(watch.WatchError, match="repeat"):
        _foundry().list_agents()
    assert len(microsoft.reads()) == 2


def test_foundry_stops_at_the_page_cap(microsoft, tmp_path):
    _configure(tmp_path, "[agent_watch]\nmax_pages = 3\n")

    def endless(request: httpx.Request) -> httpx.Response:
        number = int(request.url.params.get("after", "a0")[1:]) + 1
        return httpx.Response(200, json=_page([_foundry_agent(f"a{number}")], has_more=True))

    for number in range(6):
        microsoft.routes[FOUNDRY + (f"&after=a{number}" if number else "")] = endless
    with pytest.raises(watch.WatchError, match="3 pages"):
        _foundry().list_agents()
    assert len(microsoft.reads()) == 3


def test_foundry_stops_at_the_record_cap(microsoft, tmp_path):
    _configure(tmp_path, "[agent_watch]\nmax_agents = 2\n")
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(f"a{n}") for n in range(3)])
    with pytest.raises(watch.WatchError, match="more than 2"):
        _foundry().list_agents()


def _without(agent: dict, *path: str) -> dict:
    target = agent
    for step in path[:-1]:
        target = target[step]
    del target[path[-1]]
    return agent


@pytest.mark.parametrize("row", [
    _without(_foundry_agent(), "name"),
    _foundry_agent("has space"),
    _foundry_agent("a/b"),
    _without(_foundry_agent(), "versions"),
    _without(_foundry_agent(), "versions", "latest"),
    _without(_foundry_agent(), "versions", "latest", "version"),
    _without(_foundry_agent(), "versions", "latest", "definition"),
    _foundry_agent(version=""),
    _foundry_agent(definition={"kind": "prompt", "model": 7}),
    _foundry_agent(definition={"kind": "prompt", "model": "m", "instructions": ["be nice"]}),
    _foundry_agent(definition={"kind": "prompt", "model": "m", "tools": "all"}),
    _foundry_agent(definition="prompt"),
])
def test_foundry_refuses_an_agent_it_cannot_understand(microsoft, row):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent("fine"), row], last_id="x", first_id="fine")
    with pytest.raises(watch.WatchError) as refused:
        _foundry().list_agents()
    assert "expected form" in str(refused.value) and "contoso-ai/sales" in str(refused.value)


def test_foundry_reads_every_configured_project_with_one_sign_in(microsoft):
    other = "https://contoso-ai.services.ai.azure.com/api/projects/support"
    microsoft.routes[FOUNDRY] = _page([_foundry_agent("helper")])
    microsoft.routes[other + "/agents?api-version=v1&limit=50&order=asc"] = _page(
        [_foundry_agent("helper", version="9")])
    agents = _foundry([PROJECT, other + "/"]).list_agents()
    assert [(agent.external_id, agent.version) for agent in agents] == [
        ("contoso-ai/sales/helper", "3"), ("contoso-ai/support/helper", "9")]
    assert len(microsoft.sign_ins()) == 1


def test_one_foundry_project_failing_fails_the_run_and_says_which(microsoft):
    other = "https://contoso-ai.services.ai.azure.com/api/projects/support"
    microsoft.routes[FOUNDRY] = _page([_foundry_agent("helper")])
    microsoft.routes[other + "/agents?api-version=v1&limit=50&order=asc"] = httpx.Response(403, json={})
    with pytest.raises(watch.WatchError) as refused:
        _foundry([PROJECT, other]).list_agents()
    assert "contoso-ai/support" in str(refused.value) and "HTTP 403" in str(refused.value)


@pytest.mark.parametrize("endpoints", [
    None, "https://contoso-ai.services.ai.azure.com/api/projects/sales", [], [7],
    ["http://contoso-ai.services.ai.azure.com/api/projects/sales"],
    ["https://contoso-ai.services.ai.azure.com.evil.example/api/projects/sales"],
    ["https://evil.example/api/projects/sales"],
    ["https://user:pw@contoso-ai.services.ai.azure.com/api/projects/sales"],
    ["https://contoso-ai.services.ai.azure.com/api/projects/sales/agents"],
    ["https://contoso-ai.services.ai.azure.com/api/projects/sales?x=1"],
    ["https://contoso-ai.services.ai.azure.com/api/projects/../admin"],
    ["https://contoso-ai.services.ai.azure.com:8443/api/projects/sales"],
    [PROJECT, PROJECT],
    [f"https://r{n}.services.ai.azure.com/api/projects/p" for n in range(21)],
])
def test_foundry_endpoints_must_be_project_addresses_and_are_never_echoed(endpoints):
    settings = dict(_KEYS) if endpoints is None else {**_KEYS, "endpoints": endpoints}
    with pytest.raises(watch.WatchConfigError) as refused:
        ms.FoundryWatcher(settings)
    text = str(refused.value)
    assert "endpoints" in text and "[agent_watch.foundry]" in text
    assert "evil.example" not in text and "user:pw" not in text


def test_foundry_endpoint_host_case_does_not_matter():
    watcher = ms.FoundryWatcher({**_KEYS, "endpoints": [
        "https://Contoso-AI.Services.AI.Azure.com/api/projects/Sales"]})
    assert watcher._projects == [("contoso-ai/Sales",
                                  "https://contoso-ai.services.ai.azure.com/api/projects/Sales")]


# ------------------------------------------------------------ Copilot Studio

def _bot(**changes) -> dict:
    """One row of the Dataverse ``bot`` table as the Web API returns it."""
    return {"@odata.etag": 'W/"72201545"', "botid": "49b0be2e-d01c-ed11-b83e-000d3a572421",
            "name": "HR helper", "schemaname": "cr1a2_hrHelper",
            "publishedon": "2026-10-30T08:15:00Z", "modifiedon": "2026-11-02T09:00:00Z",
            "statecode": 0, "statuscode": 1, **changes}


def _bots(rows: list[dict], next_link: str | None = None) -> dict:
    page = {"@odata.context": f"https://{ORG}/api/data/v9.2/$metadata#bots(botid,name)", "value": rows}
    if next_link:
        page["@odata.nextLink"] = next_link
    return page


def _copilot(environments=(f"https://{ORG}",)) -> ms.CopilotStudioWatcher:
    return ms.CopilotStudioWatcher({**_KEYS, "environments": list(environments)})


def test_copilot_studio_lists_the_bot_table(microsoft):
    microsoft.routes[BOTS] = _bots([_bot()])
    agent, = _copilot().list_agents()
    assert agent == watch.ObservedAgent(
        platform="copilot_studio", external_id=f"{ORG}/49b0be2e-d01c-ed11-b83e-000d3a572421",
        name="HR helper", version="", updated_at="2026-11-02T09:00:00Z", state="enabled",
        fingerprint=watch.fingerprint({
            "publishedon": "2026-10-30T08:15:00Z", "modifiedon": "2026-11-02T09:00:00Z",
            "statecode": 0, "statuscode": 1}),
        binding_strength="observed_snapshot")


def test_copilot_studio_sends_the_documented_web_api_request(microsoft):
    microsoft.routes[BOTS] = _bots([])
    _copilot().list_agents()
    read, = microsoft.reads()
    assert str(read.url) == BOTS
    assert read.headers["accept"] == "application/json"
    assert (read.headers["odata-maxversion"], read.headers["odata-version"]) == ("4.0", "4.0")
    assert read.headers["if-none-match"] == "null"
    assert read.headers["prefer"] == "odata.maxpagesize=200"
    assert microsoft.sign_ins()[0]["scope"] == f"https://{ORG}/.default"


def test_copilot_studio_follows_the_paging_cookie_with_the_same_headers(microsoft):
    cookie = (f"https://{ORG}/api/data/v9.2/bots?$select=botid,name&$skiptoken=%3Ccookie%20"
              "pagenumber=%222%22%20pagingcookie=%22%253ccookie%2520page%253d%25221%2522%253e"
              "%253cbotid%2520last%253d%2522%257bD5026A4D-D01C-ED11-B83E-000D3A572421%257d%2522"
              "%2520%252f%253e%253c%252fcookie%253e%22%20istracking=%22False%22%20/%3E")
    sent: list[httpx.Request] = []

    def second(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=_bots([_bot(botid="70bf4d48-34cb-ed11-b596-0022481d68cd")]))

    microsoft.routes[BOTS] = _bots([_bot()], cookie)
    microsoft.routes[str(httpx.URL(cookie))] = second
    assert len(_copilot().list_agents()) == 2
    assert sent[0].url.raw_path.decode("ascii") == cookie.removeprefix(f"https://{ORG}")
    assert sent[0].headers["prefer"] == "odata.maxpagesize=200"


def test_copilot_studio_needs_only_the_id_and_the_modified_time(microsoft):
    microsoft.routes[BOTS] = _bots([{"botid": "49B0BE2E-D01C-ED11-B83E-000D3A572421",
                                     "publishedon": None, "modifiedon": "2026-11-02T09:00:00Z"}])
    agent, = _copilot().list_agents()
    assert agent.external_id == f"{ORG}/49b0be2e-d01c-ed11-b83e-000d3a572421"
    assert (agent.name, agent.state, agent.updated_at) == ("", "", "2026-11-02T09:00:00Z")
    assert agent.fingerprint == watch.fingerprint({
        "publishedon": None, "modifiedon": "2026-11-02T09:00:00Z", "statecode": None,
        "statuscode": None})


def test_copilot_studio_uses_the_schema_name_when_there_is_no_display_name(microsoft):
    microsoft.routes[BOTS] = _bots([_bot(name=None)])
    assert _copilot().list_agents()[0].name == "cr1a2_hrHelper"


@pytest.mark.parametrize("statecode, state", [(0, "enabled"), (1, "disabled"), (7, ""), (None, "")])
def test_copilot_studio_state_follows_the_state_code(microsoft, statecode, state):
    microsoft.routes[BOTS] = _bots([_bot(statecode=statecode)])
    assert _copilot().list_agents()[0].state == state


@pytest.mark.parametrize("change, differs", [
    ({"publishedon": "2026-11-20T10:00:00Z"}, True),
    ({"publishedon": None}, True),
    ({"modifiedon": "2026-11-21T10:00:00Z"}, True),
    ({"statecode": 1}, True),
    ({"statuscode": 5}, True),
    ({"name": "Renamed"}, False),
    ({"@odata.etag": 'W/"99999999"'}, False),
])
def test_copilot_studio_fingerprint_follows_published_modified_and_state(microsoft, change, differs):
    microsoft.routes[BOTS] = _bots([_bot()])
    before = _copilot().list_agents()[0].fingerprint
    microsoft.routes[BOTS] = _bots([_bot(**change)])
    assert (_copilot().list_agents()[0].fingerprint != before) is differs


@pytest.mark.parametrize("row", [
    {}, {"botid": "not-a-guid"}, {"botid": None}, _bot(modifiedon=None),
    {"botid": "70bf4d48-34cb-ed11-b596-0022481d68cd"}, _bot(statecode="active"), _bot(statecode=True),
    _bot(statuscode=1.5), _bot(publishedon=20261030), _bot(modifiedon="yesterday at noon " * 5),
    _bot(name={"x": 1}),
])
def test_copilot_studio_refuses_a_row_it_cannot_understand(microsoft, row):
    microsoft.routes[BOTS] = _bots([_bot(), row])
    with pytest.raises(watch.WatchError) as refused:
        _copilot().list_agents()
    assert "expected form" in str(refused.value) and ORG in str(refused.value)


def test_copilot_studio_keeps_the_same_bot_in_two_environments_apart(microsoft):
    other = "contoso-dev.crm.dynamics.com"
    microsoft.routes[BOTS] = _bots([_bot()])
    microsoft.routes[BOTS.replace(ORG, other)] = _bots([_bot(publishedon=None)])
    agents = _copilot([f"https://{ORG}", f"https://{other}/"]).list_agents()
    assert [agent.external_id for agent in agents] == [
        f"{ORG}/49b0be2e-d01c-ed11-b83e-000d3a572421",
        f"{other}/49b0be2e-d01c-ed11-b83e-000d3a572421"]
    # Each environment is its own resource, so each needs its own sign-in.
    assert [sign_in["scope"] for sign_in in microsoft.sign_ins()] == [
        f"https://{ORG}/.default", f"https://{other}/.default"]


def test_one_environment_failing_fails_the_run_and_says_which(microsoft):
    other = "contoso-dev.crm.dynamics.com"
    microsoft.routes[BOTS] = _bots([_bot()])
    microsoft.routes[BOTS.replace(ORG, other)] = httpx.Response(403, json={"error": {
        "code": "0x80040220", "message": "Principal user is missing prvReadbot privilege"}})
    with pytest.raises(watch.WatchError) as refused:
        _copilot([f"https://{ORG}", f"https://{other}"]).list_agents()
    assert other in str(refused.value) and "prvReadbot" not in str(refused.value)


def test_a_next_link_to_another_environment_is_refused(microsoft):
    microsoft.routes[BOTS] = _bots([_bot()], "https://evil.crm.dynamics.com/api/data/v9.2/bots?x=1")
    with pytest.raises(watch.WatchError, match="different address"):
        _copilot().list_agents()
    assert {read.url.host for read in microsoft.reads()} == {ORG}


@pytest.mark.parametrize("environments", [
    None, f"https://{ORG}", [], [7], [f"http://{ORG}"], ["https://contoso.crm4.dynamics.com.evil.example"],
    ["https://evil.example"], [f"https://user:pw@{ORG}"], [f"https://{ORG}/api/data/v9.2/bots"],
    [f"https://{ORG}?x=1"], [f"https://{ORG}:8443"], ["https://contoso.crm.microsoftdynamics.us"],
    [f"https://{ORG}", f"https://{ORG.upper()}/"],
    [f"https://org{n}.crm.dynamics.com" for n in range(21)],
])
def test_copilot_studio_environments_must_be_environment_addresses(environments):
    settings = dict(_KEYS) if environments is None else {**_KEYS, "environments": environments}
    with pytest.raises(watch.WatchConfigError) as refused:
        ms.CopilotStudioWatcher(settings)
    text = str(refused.value)
    assert "environments" in text and "[agent_watch.copilot_studio]" in text
    assert "evil.example" not in text and "user:pw" not in text


# ------------------------------------------------- through the whole check

_ALL = ('[agent_watch]\nenable = true\nplatforms = ["entra_agent_id", "foundry", "copilot_studio"]\n'
        f"[agent_watch.entra_agent_id]\n{_CREDENTIALS}"
        f'[agent_watch.foundry]\n{_CREDENTIALS}endpoints = ["{PROJECT}"]\n'
        f'[agent_watch.copilot_studio]\n{_CREDENTIALS}environments = ["https://{ORG}"]\n')


def _enroll(agent_id: str, ref: str) -> None:
    xa.enroll(agent_id, "copilot", owner="jordan@corp.test", enrolled_by="admin@corp.test")
    path = xa.registry_path()
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[agent_id]["external_ref"] = ref
    path.write_text(json.dumps(entries), encoding="utf-8")


def test_a_check_across_all_three_platforms(microsoft, tmp_path, caplog):
    from maverick import agent_drift
    _configure(tmp_path, _ALL)
    _enroll("hr-helper", f"copilot_studio:{ORG}/49B0BE2E-D01C-ED11-B83E-000D3A572421")
    _enroll("quotes", "foundry:contoso-ai/sales/quote-agent")
    microsoft.routes[GRAPH] = {"value": [_identity()]}
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(), _foundry_agent("unknown-agent")])
    microsoft.routes[BOTS] = _bots([_bot()])
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    assert {name: (row["ok"], row["listed"], row["matched"], row["not_enrolled"])
            for name, row in summary["platforms"].items()} == {
        "entra_agent_id": (True, 1, 0, 1), "foundry": (True, 2, 1, 1),
        "copilot_studio": (True, 1, 1, 0)}
    assert {row["external_ref"] for row in watch.unenrolled()} == {
        "entra_agent_id:1b7313c4-05d0-4a08-88e3-7b76c003a0a2",
        "foundry:contoso-ai/sales/unknown-agent"}
    seen = agent_drift.detail("quotes", now=T0)["config"]["discovered"]
    assert seen.pop("description")["fields"]  # the description kept beside it is checked in test_agent_watch_changes
    assert seen == {"version_digest": _prompt_fingerprint(), "seen_at": T0, "source": "foundry",
                    "binding_strength": "immutable_provider_revision"}
    assert watch.platform_view("hr-helper")["updated_at"] == "2026-11-02T09:00:00Z"
    assert all(row["ready"] for row in watch.status()["platforms"])

    everything = (json.dumps(summary) + json.dumps(watch.status()) + json.dumps(watch.unenrolled())
                  + caplog.text + watch.store_path().read_text(encoding="utf-8")
                  + agent_drift.store_path().read_text(encoding="utf-8"))
    for hidden in (SECRET, TOKEN, CLIENT, "You write quotes", "crm.example"):
        assert hidden not in everything


def test_a_new_foundry_version_becomes_a_drift_finding(microsoft, tmp_path):
    from maverick import agent_drift
    _configure(tmp_path, _ALL.replace('"entra_agent_id", "foundry", "copilot_studio"', '"foundry"'))
    _enroll("quotes", "foundry:contoso-ai/sales/quote-agent")
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    watch.sync(now=T0)
    agent_drift.approve_baseline("quotes", actor="dana@corp.test", force=True, now=T0 + 60)
    changed = {"kind": "prompt", "model": "gpt-4.1", "instructions": "You write quotes and wire money.",
               "tools": [{"type": "code_interpreter"}]}
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(version="4", definition=changed)])
    watch.sync(now=T0 + 3600)
    finding, = [f for f in agent_drift.evaluate("quotes", now=T0 + 3700)["findings"]
                if f["kind"] == "config_changed"]
    assert (finding["severity"], finding["source"]) == ("high", "discovery")
    assert watch.platform_view("quotes")["version"] == "4"


def test_secrets_stay_out_of_everything_when_checks_fail(microsoft, tmp_path, caplog):
    _configure(tmp_path, _ALL)
    microsoft.routes[GRAPH] = httpx.Response(401, json={"error": {"message": f"bad token {TOKEN}"}})
    microsoft.routes[FOUNDRY] = httpx.Response(200, content=f'{{"data": "{SECRET}"'.encode())
    microsoft.routes[BOTS] = _bots([_bot()], f"https://{ORG}/api/data/v9.2/other?key={SECRET}")
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    assert [row["ok"] for row in summary["platforms"].values()] == [False, False, False]
    everything = (json.dumps(summary) + json.dumps(watch.status()) + caplog.text
                  + watch.store_path().read_text(encoding="utf-8"))
    for hidden in (SECRET, TOKEN, CLIENT):
        assert hidden not in everything
    assert "sign-in" in summary["platforms"]["entra_agent_id"]["error"]
    assert "contoso-ai/sales" in summary["platforms"]["foundry"]["error"]
    assert ORG in summary["platforms"]["copilot_studio"]["error"]


def test_malformed_microsoft_settings_show_in_status_without_their_values(tmp_path, microsoft):
    _configure(tmp_path, '[agent_watch]\nenable = true\n'
                         'platforms = ["entra_agent_id", "foundry", "copilot_studio"]\n'
                         f'[agent_watch.entra_agent_id]\n{_CREDENTIALS}client_secret = "{SECRET}"\n'
                         f'[agent_watch.foundry]\n{_CREDENTIALS}endpoints = "https://evil.example"\n'
                         f'[agent_watch.copilot_studio]\n{_CREDENTIALS}environments = ["https://{ORG}"]\n')
    microsoft.routes[BOTS] = _bots([_bot()])
    rows = {row["name"]: row for row in watch.status()["platforms"]}
    assert rows["entra_agent_id"]["ready"] is False and rows["foundry"]["ready"] is False
    assert rows["copilot_studio"]["ready"] is True
    summary = watch.sync(now=T0)
    assert [row["ok"] for row in summary["platforms"].values()] == [False, False, True]
    everything = json.dumps(summary) + json.dumps(watch.status()) \
        + watch.store_path().read_text(encoding="utf-8")
    assert SECRET not in everything and "evil.example" not in everything
    # A platform whose settings are refused is never contacted.
    assert {request.url.host for request in microsoft.requests} == {"login.microsoftonline.com", ORG}


def test_checks_only_ever_reach_the_fixed_microsoft_addresses(microsoft, tmp_path):
    _configure(tmp_path, _ALL)
    microsoft.routes[GRAPH] = {"value": [_identity()]}
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    microsoft.routes[BOTS] = _bots([_bot()])
    watch.sync(now=T0)
    assert [(request.method, str(request.url)) for request in microsoft.requests] == [
        ("POST", LOGIN), ("GET", GRAPH), ("POST", LOGIN), ("GET", FOUNDRY), ("POST", LOGIN), ("GET", BOTS)]


# ------------------------------------------- the description kept beside a fingerprint

def test_entra_describes_the_fields_its_fingerprint_covers(microsoft):
    microsoft.routes[GRAPH] = {"value": [_identity(accountEnabled=False)]}
    agent, = _entra().list_agents()
    assert agent.details["fields"] == {
        "name": "My Agent Identity", "enabled": False,
        "blueprint": "00001111-aaaa-2222-bbbb-3333cccc4444", "identity_type": "ServiceIdentity"}


def test_foundry_describes_model_tools_and_a_digest_of_the_instructions(microsoft):
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    agent, = _foundry().list_agents()
    fields = agent.details["fields"]
    assert (fields["name"], fields["version"], fields["state"], fields["kind"], fields["model"]) == (
        "quote-agent", "3", "enabled", "prompt", "gpt-4.1")
    assert fields["tools"] == ["code_interpreter", "mcp:crm"]
    assert set(fields["tool_settings"]) == {"code_interpreter", "mcp:crm"}
    assert fields["instructions"] == "sha256:" + _sha("You write quotes.")[:16]
    shown = repr(agent.details)
    for text in ("You write quotes", "crm.example", "server_url"):
        assert text not in shown


def test_foundry_description_follows_a_change_to_each_defined_field(microsoft):
    from maverick import agent_watch_changes as changes
    microsoft.routes[FOUNDRY] = _page([_foundry_agent()])
    before, = _foundry().list_agents()
    microsoft.routes[FOUNDRY] = _page([_foundry_agent(version="4", definition={
        "kind": "prompt", "model": "gpt-4.1-mini", "instructions": "Be brief.",
        "tools": [{"type": "function", "name": "send_email", "parameters": {"type": "object"}},
                  {"type": "code_interpreter"}, {"type": "mcp", "server_label": "crm",
                                                 "server_url": "https://crm.example/other"}]})])
    after, = _foundry().list_agents()
    text = changes.compare("foundry", before.details, after.details)["summary"]
    assert text == (
        "quote-agent changed on Microsoft Foundry: version 3 -> 4; model gpt-4.1 -> gpt-4.1-mini; "
        "tool added: function:send_email; tool settings changed: mcp:crm (Second Shift keeps a "
        "fingerprint of the settings, not the settings); instructions changed (Second Shift keeps "
        "a fingerprint of the instructions, not the text).")


def test_foundry_labels_are_bounded_for_odd_tools(microsoft):
    odd = _foundry_agent(definition={"kind": "prompt", "model": "m", "instructions": "x",
                                     "tools": [{"type": "function", "name": "n" * 500}, "text", 7,
                                               {"type": "function", "name": "dup"},
                                               {"type": "function", "name": "dup", "extra": 1}]})
    microsoft.routes[FOUNDRY] = _page([odd])
    agent, = _foundry().list_agents()
    tools = agent.details["fields"]["tools"]
    assert all(len(tool) <= 80 for tool in tools)
    assert {"tool", "function:dup", "function:dup#"} <= set(tools)


def test_copilot_studio_describes_the_times_and_state_it_reads(microsoft):
    microsoft.routes[BOTS] = _bots([_bot()])
    agent, = _copilot().list_agents()
    assert agent.details["fields"] == {
        "name": "HR helper", "state": "enabled", "status_code": "1",
        "published": "2026-10-30T08:15:00Z", "modified": "2026-11-02T09:00:00Z"}
