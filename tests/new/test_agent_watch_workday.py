"""The Workday platform check against answers shaped like the documented
ones. Nothing here talks to Workday: every request is answered by a stand-in."""
from __future__ import annotations

import hashlib
import json
import logging
from contextlib import contextmanager

import httpx
import pytest

from maverick import agent_watch as watch
from maverick import agent_watch_workday as wd
from maverick import external_agents as xa

T0 = 20_000 * 86400
TENANT = "acme_prod"
GATEWAY = "us.agent.workday.com"
SIGN_IN = f"https://{GATEWAY}/auth/oauth2/{TENANT}/token"
LIST = f"https://{GATEWAY}/asor/v1/agentDefinition"
#: Shaped like real credentials so the secret checks mean something.
CLIENT = "NDhiZmE2M2QtYjA4OS00YzRjLWFkZTEtMWZlYzQ0ZjE5ZDcy"  # pragma: allowlist secret
SECRET = "Zx8~Q.fake-client-secret_4hT9"  # pragma: allowlist secret
REFRESH = "9gq2x7m4k1fakeRefreshToken0p8w5z3v6n1b4c7d0e"  # pragma: allowlist secret
TOKEN = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."  # pragma: allowlist secret
         "eyJhdWQiOiJmYWtlIiwiaXNzIjoiZmFrZSJ9.c2lnbmF0dXJlLW5vdC1yZWFs")  # pragma: allowlist secret

DEFINITION = "9a1f0c2e4b6d8f00112233445566aabb"
SECOND = "0b2e1d3f5a7c9e00112233445566ccdd"
PURPOSE = "A Workday agent for changing a business title with Agent Gateway"

_KEYS = {"client_id_env": "WATCH_WD_CLIENT", "client_secret_env": "WATCH_WD_SECRET",
         "refresh_token_env": "WATCH_WD_REFRESH"}
_PLACE = {"region": "us", "tenant": TENANT}
_CREDENTIALS = ('client_id_env = "WATCH_WD_CLIENT"\nclient_secret_env = "WATCH_WD_SECRET"\n'
                'refresh_token_env = "WATCH_WD_REFRESH"\n')


class Workday:
    """A stand-in for Workday's Agent Gateway: its sign-in endpoint, plus
    whatever answers the test puts in ``routes`` (address -> body, or a
    function of the request). A request for anything else fails the test."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.routes: dict[str, object] = {}
        self.unexpected: list[str] = []
        self.sign_in: httpx.Response | None = None

    def answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "POST" and request.url.path.startswith("/auth/oauth2/"):
            return self.sign_in or httpx.Response(200, json={
                "access_token": TOKEN, "refresh_token": REFRESH, "token_type": "Bearer",
                "expires_in": 14400})
        route = self.routes.get(str(request.url))
        if route is None:
            self.unexpected.append(f"{request.method} {request.url}")
            return httpx.Response(404, json={"error": "Resource not found"})
        if callable(route):
            return route(request)
        return route if isinstance(route, httpx.Response) else httpx.Response(200, json=route)

    def lists(self, *definitions: dict) -> None:
        """Answer the list as the documented one does: ``total`` and ``data``."""
        self.routes[LIST] = {"total": len(definitions), "data": list(definitions)}

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
    monkeypatch.setenv("WATCH_WD_CLIENT", CLIENT)
    monkeypatch.setenv("WATCH_WD_SECRET", SECRET)
    monkeypatch.setenv("WATCH_WD_REFRESH", REFRESH)
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
def workday(monkeypatch):
    from maverick.tools import _ssrf
    service = Workday()

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
    assert all(request.url.host.endswith(".agent.workday.com") for request in service.requests)
    # The access token is used for one run and never kept.
    assert watch._TOKENS == {}


def _configure(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config
    config.reset_config_cache()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _in_one_order(value):
    if isinstance(value, dict):
        return {key: _in_one_order(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((_in_one_order(item) for item in value), key=_canonical)
    return value


def _list_hash(items: list) -> str:
    return _sha(_canonical(_in_one_order(items)))


def _watcher(**changes) -> wd.WorkdayWatcher:
    return wd.WorkdayWatcher({**_KEYS, **_PLACE, **changes})


# ------------------------------- definitions as the documented answer shows them

_SKILLS = [{"id": "changeTitle_1", "name": "Change Title",
            "description": "This skill gets worker information and changes a business title.",
            "inputModes": [{"type": "application/json"}], "outputModes": [{"type": "application/json"}]}]
_RESOURCES = [
    {"description": "Internal Auth Check", "tool_name": "internalAuthCheck",
     "agent_resource": {"id": "6bbfa713d3851000081920672a0f0009",
                        "descriptor": "trident/userAuth/checkAuth (GET) (v1 -  )"}},
    {"description": "Change Business Title", "tool_name": "changeBusinessTitle",
     "agent_resource": {"id": "c2ffb30053964fbfa7a46dcfa577adb1",
                        "descriptor": "api/workers/businessTitleChanges/create (POST) (v1 -  )"}},
    {"description": "Get Workers", "tool_name": "getWorkers",
     "agent_resource": {"id": "94a39e71541b468fa895955508287acd",
                        "descriptor": "api/workers/view (GET) (v1 -  )"}}]
_CONFIG = [{"skillId": "changeTitle_1",
            "executionMode": {"descriptor": "Delegate", "id": "d785eba56e9c100035d336a043ff0000"},
            "workdayResources": _RESOURCES}]


def _definition(identifier: str = DEFINITION, **changes) -> dict:
    """One agent definition as Workday's sample answer shows it, with its id."""
    return {"id": identifier, "version": "v1",
            "provider": {"descriptor": "Self-Built", "id": "9030a823ae1a10002d624e2d637e0000"},
            "skills": _SKILLS, "url": "https://changetitleagent.example", "description": PURPOSE,
            "capabilities": {"pushNotifications": False, "stateTransitionHistory": False,
                             "streaming": False},
            "workdayConfig": _CONFIG,
            "platform": {"id": "b49b32cfdbef10002184b61535490000", "descriptor": "Google Agentspace",
                         "reference_id": "GOOGLE_AGENTSPACE"},
            "name": "Change Business Title Agent", "supportsAuthenticatedExtendedCard": False,
            **changes}


def _fingerprint(**changes) -> str:
    """The fingerprint of ``_definition()``, worked out the long way."""
    return watch.fingerprint({
        "name": "Change Business Title Agent", "version": "v1",
        "url": "https://changetitleagent.example", "externalAgentID": None, "externalTenantID": None,
        "provider": "9030a823ae1a10002d624e2d637e0000", "platform": "b49b32cfdbef10002184b61535490000",
        "description": _sha(PURPOSE),
        "capabilities": {"pushNotifications": False, "stateTransitionHistory": False, "streaming": False},
        "supportsAuthenticatedExtendedCard": False, "defaultInputModes": None,
        "defaultOutputModes": None, "skills": _list_hash(_SKILLS), "workdayConfig": _list_hash(_CONFIG),
        **changes})


# ------------------------------------------------------------------- reading

def test_lists_the_agent_definitions_of_the_tenant(workday):
    workday.lists(_definition())
    agent, = _watcher().list_agents()
    assert agent == watch.ObservedAgent(
        platform="workday", external_id=f"{TENANT}/{DEFINITION}", name="Change Business Title Agent",
        version="v1", updated_at="", state="", fingerprint=_fingerprint(),
        binding_strength="observed_snapshot")


def test_sends_the_documented_request_once(workday):
    workday.lists(_definition())
    _watcher().list_agents()
    read, = workday.reads()
    assert str(read.url) == LIST and read.url.query == b""
    assert read.headers["authorization"] == f"Bearer {TOKEN}"
    assert read.headers["wd-agent-tenant-alias"] == TENANT
    assert read.headers["accept"] == "application/json"


def test_signs_in_with_the_refresh_token_of_the_integration_user(workday):
    workday.lists()
    assert _watcher().list_agents() == []
    assert workday.sign_ins() == [{"grant_type": "refresh_token", "refresh_token": REFRESH,
                                   "client_id": CLIENT, "client_secret": SECRET}]
    sign_in = workday.requests[0]
    assert str(sign_in.url) == SIGN_IN
    assert sign_in.headers["content-type"] == "application/x-www-form-urlencoded"
    assert "authorization" not in sign_in.headers


def test_the_region_and_tenant_choose_the_gateway_address(workday):
    place = "https://eu.agent.workday.com/asor/v1/agentDefinition"
    workday.routes[place] = {"total": 0, "data": []}
    assert _watcher(region=" EU ", tenant="stark-industries").list_agents() == []
    assert [str(request.url) for request in workday.requests] == [
        "https://eu.agent.workday.com/auth/oauth2/stark-industries/token", place]
    assert workday.reads()[0].headers["wd-agent-tenant-alias"] == "stark-industries"


def test_a_token_is_never_kept_between_runs(workday):
    workday.lists(_definition())
    watcher = _watcher()
    watcher.list_agents()
    watcher.list_agents()
    assert len(workday.sign_ins()) == 2 and watch._TOKENS == {}


def test_never_keeps_descriptions_skills_or_resources(workday):
    workday.lists(_definition())
    agent, = _watcher().list_agents()
    for text in ("changing a business title", "worker information", "businessTitleChanges", "checkAuth"):
        assert text not in repr(agent)


def test_everything_but_the_id_is_optional(workday):
    workday.lists({"id": DEFINITION})
    agent, = _watcher().list_agents()
    assert (agent.name, agent.state, agent.version, agent.updated_at) == ("", "", "", "")
    assert agent.fingerprint == watch.fingerprint({
        "name": None, "version": None, "url": None, "externalAgentID": None, "externalTenantID": None,
        "provider": None, "platform": None, "description": None,
        "capabilities": {"pushNotifications": None, "stateTransitionHistory": None, "streaming": None},
        "supportsAuthenticatedExtendedCard": None, "defaultInputModes": None,
        "defaultOutputModes": None, "skills": None, "workdayConfig": None})


def test_a_reference_id_is_accepted_as_an_id(workday):
    workday.lists(_definition("Agent_Definition=CHANGE_TITLE.v1"))
    assert _watcher().list_agents()[0].external_id == f"{TENANT}/Agent_Definition=CHANGE_TITLE.v1"


def _ambient() -> list[dict]:
    return [{**_CONFIG[0], "executionMode": {"descriptor": "Ambient",
                                             "id": "d785eba56e9c100035d336a043ff0001"}}]


def _one_more_resource() -> list[dict]:
    payroll = {"description": "Read pay results", "tool_name": "getPayResults",
               "agent_resource": {"id": "77f25aa828701000149e3f8767a80000"}}
    return [{**_CONFIG[0], "workdayResources": [*_RESOURCES, payroll]}]


@pytest.mark.parametrize("change, differs", [
    ({"name": "Renamed"}, True),
    ({"version": "v2"}, True),
    ({"url": "https://elsewhere.example"}, True),
    ({"description": PURPOSE + " and pay"}, True),
    ({"provider": {"descriptor": "Other", "id": "9030a823ae1a10002d624e2d637e9999"}}, True),
    ({"platform": {"id": "b49b32cfdbef10002184b61535499999"}}, True),
    ({"externalAgentID": "agent-7"}, True),
    ({"externalTenantID": "tenant-7"}, True),
    ({"capabilities": {"pushNotifications": True, "stateTransitionHistory": False,
                       "streaming": False}}, True),
    ({"supportsAuthenticatedExtendedCard": True}, True),
    ({"defaultInputModes": [{"type": "text/plain"}]}, True),
    ({"defaultOutputModes": [{"type": "text/plain"}]}, True),
    ({"skills": [{**_SKILLS[0], "description": "This skill changes pay."}]}, True),
    ({"skills": [*_SKILLS, {"id": "second", "name": "Second", "description": "Another skill."}]}, True),
    ({"workdayConfig": _ambient()}, True),
    ({"workdayConfig": _one_more_resource()}, True),
    ({"workdayConfig": []}, True),
    # Display details, and anything Workday adds later, are not configuration.
    ({"overview": "Welcome. How may I help?"}, False),
    ({"iconUrl": "https://changetitleagent.example/icon.png"}, False),
    ({"documentationUrl": "https://changetitleagent.example/docs"}, False),
    ({"somethingNew": {"added": "later"}}, False),
    ({"provider": {"descriptor": "Built in house", "id": "9030a823ae1a10002d624e2d637e0000"}}, False),
])
def test_fingerprint_follows_what_defines_the_agent(workday, change, differs):
    workday.lists(_definition())
    before = _watcher().list_agents()[0].fingerprint
    assert before == _fingerprint()
    workday.lists(_definition(**change))
    assert (_watcher().list_agents()[0].fingerprint != before) is differs


def test_the_order_workday_sends_lists_in_does_not_matter(workday):
    second = {"name": "Second", "id": "second", "description": "Another skill.",
              "tags": [{"tag": "hr"}, {"tag": "read-only"}]}
    workday.lists(_definition(skills=[*_SKILLS, second]))
    before = _watcher().list_agents()[0].fingerprint
    shuffled = {"description": "Another skill.", "tags": [{"tag": "read-only"}, {"tag": "hr"}],
                "id": "second", "name": "Second"}
    config = [{**_CONFIG[0], "workdayResources": list(reversed(_RESOURCES))}]
    workday.lists(_definition(skills=[shuffled, *_SKILLS], workdayConfig=config))
    assert _watcher().list_agents()[0].fingerprint == before


# ------------------------------------------- one answer must be the whole list

@pytest.mark.parametrize("total", [2, 25, 0])
def test_a_count_that_does_not_match_is_an_error_never_a_shorter_list(workday, total):
    workday.routes[LIST] = {"total": total, "data": [_definition()]}
    with pytest.raises(watch.WatchError, match="does not match") as stopped:
        _watcher().list_agents()
    assert "incomplete" in str(stopped.value) and len(workday.reads()) == 1


@pytest.mark.parametrize("page", [
    {"data": [_definition()]},                        # no total to check the list against
    {"total": "1", "data": [_definition()]},
    {"total": True, "data": [_definition()]},
    {"total": 1.0, "data": [_definition()]},
    {"total": None, "data": [_definition()]},
    {"total": 1, "data": "none"},
    {"total": 1, "data": [["id", DEFINITION]]},
    {"total": 1, "value": [_definition()]},
    httpx.Response(200, content=b"[]"),
    httpx.Response(200, content=b"<html>Service unavailable</html>"),
])
def test_refuses_a_list_it_cannot_understand(workday, page):
    workday.routes[LIST] = page
    with pytest.raises(watch.WatchError, match="expected form") as refused:
        _watcher().list_agents()
    assert "unavailable" not in str(refused.value)


def test_nothing_in_the_answer_is_followed(workday):
    workday.routes[LIST] = {"total": 1, "data": [_definition()],
                            "next": "https://evil.example/asor/v1/agentDefinition?offset=1",
                            "@odata.nextLink": f"{LIST}?offset=1"}
    assert len(_watcher().list_agents()) == 1
    assert [str(request.url) for request in workday.requests] == [SIGN_IN, LIST]


def test_stops_at_the_record_cap(workday, tmp_path):
    _configure(tmp_path, "[agent_watch]\nmax_agents = 2\n")
    workday.lists(*(_definition(f"{number:032x}") for number in range(1, 4)))
    with pytest.raises(watch.WatchError, match="more than 2"):
        _watcher().list_agents()


def test_the_same_id_listed_twice_is_an_error(workday):
    workday.lists(_definition(), _definition(SECOND), _definition(version="v2"))
    with pytest.raises(watch.WatchError, match="more than once"):
        _watcher().list_agents()


@pytest.mark.parametrize("row", [
    {}, {"id": None}, {"id": 7}, {"id": ""}, {"id": "has space"}, {"id": "a/b"}, {"id": "x" * 101},
    _definition(name=["a"]), _definition(version=2), _definition(url={"href": "x"}),
    _definition(description=7), _definition(provider="Self-Built"), _definition(provider={"id": 7}),
    _definition(platform=["OTHER"]), _definition(capabilities="none"),
    _definition(capabilities={"streaming": "yes"}), _definition(supportsAuthenticatedExtendedCard="no"),
    _definition(skills="all"), _definition(skills={"id": "one"}), _definition(workdayConfig="none"),
    _definition(defaultInputModes="text/plain"), _definition(externalAgentID=7),
])
def test_refuses_a_definition_it_cannot_understand(workday, row):
    workday.lists(_definition(SECOND), row)
    with pytest.raises(watch.WatchError, match="expected form"):
        _watcher().list_agents()


def test_says_when_the_security_group_cannot_view_agents(workday):
    workday.routes[LIST] = httpx.Response(403, json={
        "error": f"User has insufficient permissions. token={TOKEN}"})
    with pytest.raises(watch.WatchError) as refused:
        _watcher().list_agents()
    text = str(refused.value)
    assert "permission" in text and TOKEN not in text and "insufficient" not in text


# ------------------------------------------------------------------- sign-in

def test_says_when_the_sign_in_is_refused(workday):
    workday.sign_in = httpx.Response(400, json={
        "error": "invalid_grant", "error_description": f"refresh token {REFRESH} has expired"})
    with pytest.raises(watch.WatchError) as refused:
        _watcher().list_agents()
    text = str(refused.value)
    assert "sign-in" in text and "HTTP 400" in text and "refresh token" in text
    assert REFRESH not in text and SECRET not in text and CLIENT not in text
    assert workday.reads() == []


@pytest.mark.parametrize("answer", [
    {"token_type": "Bearer", "expires_in": 14400},
    {"access_token": "", "token_type": "Bearer"},
    {"access_token": "two words", "token_type": "Bearer"},
    {"access_token": ["a"], "token_type": "Bearer"},
    {"access_token": TOKEN, "token_type": "mac"},
    [TOKEN],
])
def test_a_sign_in_answer_without_a_usable_token_is_refused(workday, answer):
    workday.sign_in = httpx.Response(200, json=answer)
    with pytest.raises(watch.WatchError, match="no usable token") as refused:
        _watcher().list_agents()
    assert TOKEN not in str(refused.value) and workday.reads() == []


def test_a_sign_in_answer_that_is_not_json_is_refused(workday):
    workday.sign_in = httpx.Response(200, content=f"<html>{REFRESH}</html>".encode())
    with pytest.raises(watch.WatchError, match="no usable token") as refused:
        _watcher().list_agents()
    assert REFRESH not in str(refused.value)


@pytest.mark.parametrize("expires_in", ["14400", 14400, None])
def test_the_lifetime_may_be_text_or_a_number(workday, expires_in):
    # Workday says the type differs between environments; the check ignores it.
    workday.sign_in = httpx.Response(200, json={"access_token": TOKEN, "token_type": "bearer",
                                                "expires_in": expires_in})
    workday.lists(_definition())
    assert len(_watcher().list_agents()) == 1


@pytest.mark.parametrize("variable, setting", [("WATCH_WD_CLIENT", "client_id_env"),
                                               ("WATCH_WD_SECRET", "client_secret_env"),
                                               ("WATCH_WD_REFRESH", "refresh_token_env")])
def test_a_credential_that_is_not_set_is_named_by_its_setting(workday, monkeypatch, variable, setting):
    monkeypatch.delenv(variable)
    with pytest.raises(watch.WatchError) as missing:
        _watcher().list_agents()
    assert f"{setting} in [agent_watch.workday] is not set" in str(missing.value)
    assert workday.requests == []


# ------------------------------------------------------------------ settings

@pytest.mark.parametrize("settings, words", [
    ({**_PLACE}, "client_id_env"),
    ({**_KEYS, **_PLACE, "client_id_env": CLIENT + " "}, "client_id_env"),
    ({**_KEYS, **_PLACE, "client_secret_env": SECRET}, "client_secret_env"),
    ({**_KEYS, **_PLACE, "refresh_token_env": 7}, "refresh_token_env"),
    ({**_KEYS, **_PLACE, "client_secret": SECRET}, "client_secret_env"),
    ({**_KEYS, **_PLACE, "refresh_token": REFRESH}, "refresh_token_env"),
    ({**_KEYS, **_PLACE, "token_url": "https://evil.example/token"}, "token_url"),
    ({**_KEYS, **_PLACE, "endpoint": "https://evil.example/asor/v1/agentDefinition"}, "endpoint"),
    ({**_KEYS, **_PLACE, SECRET: "x"}, "does not know"),
    ({**_KEYS, "tenant": TENANT}, "region"),
    ({**_KEYS, "tenant": TENANT, "region": 7}, "region"),
    ({**_KEYS, "tenant": TENANT, "region": "mars"}, "region"),
    ({**_KEYS, "tenant": TENANT, "region": "https://evil.example"}, "region"),
    ({**_KEYS, "tenant": TENANT, "region": "us.evil.example/x?"}, "region"),
    ({**_KEYS, "region": "us"}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": ["acme"]}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": ""}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": "acme/../other"}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": "acme?x=1"}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": "acme prod"}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": "acme.evil.example"}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": "https://evil.example/acme"}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": SECRET}, "tenant"),
    ({**_KEYS, "region": "us", "tenant": "x" * 64}, "tenant"),
])
def test_settings_are_checked_and_never_echoed(settings, words):
    with pytest.raises(watch.WatchConfigError) as refused:
        wd.WorkdayWatcher(settings)
    text = str(refused.value)
    assert words in text and "[agent_watch.workday]" in text
    for hidden in (SECRET, REFRESH, CLIENT, "evil.example", "mars", "acme"):
        assert hidden not in text


# ------------------------------------------------- through the whole check

_WATCHING = ('[agent_watch]\nenable = true\nplatforms = ["workday"]\n'
             f'[agent_watch.workday]\n{_CREDENTIALS}region = "us"\ntenant = "{TENANT}"\n')


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


def test_the_workday_check_is_registered_out_of_the_box():
    assert "agent_watch_workday" in watch._WATCHER_MODULES
    assert "workday" in watch.registered()


def test_a_check_matches_enrolled_agents_and_lists_the_rest(workday, tmp_path, caplog):
    from maverick import agent_drift
    _configure(tmp_path, _WATCHING)
    # The reference is matched whatever case it was typed in.
    _enroll("title-agent", f"workday:{TENANT.upper()}/{DEFINITION.upper()}")
    workday.lists(_definition(), _definition(SECOND, name="Unclaimed agent"))
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    row = summary["platforms"]["workday"]
    assert (row["ok"], row["listed"], row["matched"], row["not_enrolled"]) == (True, 2, 1, 1)
    unclaimed, = watch.unenrolled()
    assert (unclaimed["external_ref"], unclaimed["name"]) == (f"workday:{TENANT}/{SECOND}",
                                                             "Unclaimed agent")
    view = watch.platform_view("title-agent")
    assert (view["listed"], view["name"], view["version"], view["state"], view["updated_at"]) == (
        True, "Change Business Title Agent", "v1", "", "")
    seen = agent_drift.detail("title-agent", now=T0)["config"]["discovered"]
    assert seen.pop("description")["fields"]  # the description kept beside it is checked in test_agent_watch_changes
    assert seen == {"version_digest": _fingerprint(), "seen_at": T0, "source": "workday",
                    "binding_strength": "observed_snapshot"}
    assert all(platform["ready"] for platform in watch.status()["platforms"])

    everything = (json.dumps(summary) + json.dumps(watch.status()) + json.dumps(watch.unenrolled())
                  + caplog.text + watch.store_path().read_text(encoding="utf-8")
                  + agent_drift.store_path().read_text(encoding="utf-8"))
    for hidden in (SECRET, REFRESH, TOKEN, CLIENT, "changing a business title", "businessTitleChanges"):
        assert hidden not in everything


def test_a_changed_definition_becomes_a_drift_finding(workday, tmp_path):
    from maverick import agent_drift
    _configure(tmp_path, _WATCHING)
    _enroll("title-agent", f"workday:{TENANT}/{DEFINITION}")
    workday.lists(_definition())
    watch.sync(now=T0)
    agent_drift.approve_baseline("title-agent", actor="dana@corp.test", force=True, now=T0 + 60)
    assert [f for f in agent_drift.evaluate("title-agent", now=T0 + 120)["findings"]
            if f["kind"] == "config_changed"] == []
    # The agent is given one more Workday resource and now runs without a person.
    workday.lists(_definition(workdayConfig=[{**_one_more_resource()[0],
                                              "executionMode": _ambient()[0]["executionMode"]}]))
    watch.sync(now=T0 + 3600)
    finding, = [f for f in agent_drift.evaluate("title-agent", now=T0 + 3700)["findings"]
                if f["kind"] == "config_changed"]
    assert (finding["severity"], finding["source"]) == ("high", "discovery")


def test_workday_failing_does_not_stop_another_platform(workday, tmp_path, monkeypatch):
    monkeypatch.setitem(watch._FACTORIES, "other", lambda settings: _Steady())
    _configure(tmp_path, _WATCHING.replace('["workday"]', '["workday", "other"]'))
    _enroll("title-agent", f"workday:{TENANT}/{DEFINITION}")
    workday.lists(_definition())
    assert watch.sync(now=T0)["succeeded"] == 2
    workday.routes[LIST] = {"total": 40, "data": [_definition()]}
    summary = watch.sync(now=T0 + 3600)
    assert {name: row["ok"] for name, row in summary["platforms"].items()} == {
        "workday": False, "other": True}
    assert "does not match" in summary["platforms"]["workday"]["error"]
    # What was known about the failed platform is kept as it was.
    view = watch.platform_view("title-agent")
    assert (view["listed"], view["last_seen_at"], view["missing_runs"]) == (True, T0, 0)
    failed = next(row for row in watch.status()["platforms"] if row["name"] == "workday")
    assert (failed["last_success_at"], failed["failures_in_a_row"], failed["listed"]) == (T0, 1, 1)


def test_secrets_stay_out_of_everything_when_the_check_fails(workday, tmp_path, caplog):
    _configure(tmp_path, _WATCHING)
    workday.routes[LIST] = httpx.Response(401, json={"error": f"invalid token {TOKEN}"})
    with caplog.at_level(logging.DEBUG):
        first = watch.sync(now=T0)
    workday.sign_in = httpx.Response(401, json={
        "error": "invalid_client", "error_description": f"{CLIENT} {SECRET} {REFRESH}"})
    with caplog.at_level(logging.DEBUG):
        second = watch.sync(now=T0 + 60)
    workday.sign_in = None
    workday.routes[LIST] = httpx.Response(200, content=f'{{"total": 1, "data": "{REFRESH}"'.encode())
    with caplog.at_level(logging.DEBUG):
        third = watch.sync(now=T0 + 120)
    runs = (first, second, third)
    assert [run["platforms"]["workday"]["ok"] for run in runs] == [False, False, False]
    everything = ("".join(json.dumps(run) for run in runs) + json.dumps(watch.status()) + caplog.text
                  + watch.store_path().read_text(encoding="utf-8"))
    for hidden in (SECRET, REFRESH, TOKEN, CLIENT):
        assert hidden not in everything
    assert "HTTP 401" in first["platforms"]["workday"]["error"]
    assert "refused this check's sign-in" in second["platforms"]["workday"]["error"]
    assert "expected form" in third["platforms"]["workday"]["error"]


def test_malformed_settings_show_in_status_without_their_values(workday, tmp_path):
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = ["workday"]\n'
                         f'[agent_watch.workday]\n{_CREDENTIALS}refresh_token = "{REFRESH}"\n'
                         'region = "us"\ntenant = "https://evil.example"\n')
    row, = watch.status()["platforms"]
    assert row["ready"] is False and "refresh_token_env" in row["problem"]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["workday"]["ok"] is False
    everything = (json.dumps(summary) + json.dumps(watch.status())
                  + watch.store_path().read_text(encoding="utf-8"))
    assert REFRESH not in everything and "evil.example" not in everything
    # A platform whose settings are refused is never contacted.
    assert workday.requests == []


def test_a_check_only_ever_reaches_the_two_fixed_addresses(workday, tmp_path):
    _configure(tmp_path, _WATCHING)
    workday.lists(_definition())
    watch.sync(now=T0)
    assert [(request.method, str(request.url)) for request in workday.requests] == [
        ("POST", SIGN_IN), ("GET", LIST)]


# ------------------------------------------- the description kept beside a fingerprint

def test_describes_the_definition_with_skill_names_and_digests(workday):
    workday.lists(_definition())
    agent, = _watcher().list_agents()
    fields = agent.details["fields"]
    assert (fields["name"], fields["version"], fields["extended_card"]) == (
        "Change Business Title Agent", "v1", False)
    assert fields["skills"] and all(isinstance(name, str) for name in fields["skills"])
    for key in ("skill_definitions", "workday_config", "description", "url"):
        assert fields[key].startswith("sha256:")
    shown = repr(agent.details)
    for text in (PURPOSE, "changetitleagent.example", "worker information", "checkAuth"):
        assert text not in shown


def test_a_changed_definition_is_told_in_words(workday):
    from maverick import agent_watch_changes as changes
    workday.lists(_definition())
    before, = _watcher().list_agents()
    workday.lists(_definition(version="v2", description="Something else entirely."))
    after, = _watcher().list_agents()
    text = changes.compare("workday", before.details, after.details)["summary"]
    assert text == ("Change Business Title Agent changed on Workday: version v1 -> v2; description "
                    "changed (Second Shift keeps a fingerprint of the description, not the text). "
                    "Workday does not say who changed the definition or when.")
