"""Platform checks for outside agents: the settings, the watcher interface,
the guarded reads, the sign-in helper, matching, the saved record and the read
models. Nothing here talks to a real platform."""
from __future__ import annotations

import json
import logging
import os
import threading
from contextlib import contextmanager

import httpx
import pytest

from maverick import agent_drift as drift
from maverick import agent_watch as watch
from maverick import (
    agent_watch_microsoft,  # noqa: F401 -- registers the built-in checks before any test copies the registry
)
from maverick import external_agents as xa

DAY = 86400
T0 = 20_000 * DAY
AGENT = "sf-quotebot"
#: Shaped like real credentials so the secret checks mean something.
SECRET = "Zx8~Q.fake-client-secret_4hT9"  # pragma: allowlist secret
TOKEN = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."  # pragma: allowlist secret
         "eyJhdWQiOiJmYWtlIiwiaXNzIjoiZmFrZSJ9.c2lnbmF0dXJlLW5vdC1yZWFs")  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_AGENT_WATCH", raising=False)
    monkeypatch.delenv("MAVERICK_AGENT_DRIFT", raising=False)
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    # A test's own registrations and cached sign-ins end with the test.
    monkeypatch.setattr(watch, "_FACTORIES", dict(watch._FACTORIES))
    monkeypatch.setattr(watch, "_TOKENS", {})
    FakeWatcher.agents = {}
    FakeWatcher.failure = {}
    FakeWatcher.calls = []
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _configure(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config
    config.reset_config_cache()


# -------------------------------------------------- how a platform is added

class FakeWatcher:
    """Everything a new platform has to provide: a ``name``, a constructor
    that checks its own ``[agent_watch.<name>]`` table, and ``list_agents``.
    A real one reads its platform through ``watch.Reader``; this one answers
    from what the test put in ``agents``."""

    agents: dict[str, list[watch.ObservedAgent]] = {}
    failure: dict[str, Exception] = {}
    calls: list[str] = []

    def __init__(self, name: str, settings: dict) -> None:
        if not isinstance(settings.get("site"), str) or not settings["site"]:
            raise watch.WatchConfigError(f"[agent_watch.{name}] needs site.")
        self.name = name

    def list_agents(self) -> list[watch.ObservedAgent]:
        FakeWatcher.calls.append(self.name)
        if self.name in FakeWatcher.failure:
            raise FakeWatcher.failure[self.name]
        return list(FakeWatcher.agents.get(self.name, []))


def _seen(external_id: str, *, platform: str = "fake", config: str = "v1", name: str = "",
          state: str = "enabled", version: str = "1", strong: bool = False) -> watch.ObservedAgent:
    return watch.ObservedAgent(
        platform=platform, external_id=external_id, name=name or external_id.title(),
        version=version, updated_at="2026-11-01T10:00:00Z", state=state,
        fingerprint=watch.fingerprint({"config": config}),
        binding_strength=watch.IMMUTABLE_REVISION if strong else watch.OBSERVED_SNAPSHOT)


_WATCHING = ('[agent_watch]\nenable = true\nplatforms = ["fake"]\n{extra}\n'
             '[agent_watch.fake]\nsite = "one"\n')


@pytest.fixture
def fake(tmp_path):
    """Platform checks switched on with one platform called "fake"."""
    watch.register("fake", lambda settings: FakeWatcher("fake", settings))
    _configure(tmp_path, _WATCHING.format(extra=""))
    return FakeWatcher


def _two_platforms(tmp_path, extra: str = "") -> None:
    for name in ("fake", "other"):
        watch.register(name, lambda settings, name=name: FakeWatcher(name, settings))
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = ["fake", "other"]\n'
                         f'{extra}\n[agent_watch.fake]\nsite = "one"\n'
                         '[agent_watch.other]\nsite = "two"\n')


def _enroll(agent_id: str = AGENT, ref: str | None = "fake:bot-1") -> None:
    xa.enroll(agent_id, "custom", owner="jordan@corp.test", enrolled_by="admin@corp.test")
    if ref is not None:
        _set_ref(agent_id, ref)


def _set_ref(agent_id: str, ref) -> None:
    """Enrollment does not write ``external_ref`` yet, so the test does."""
    from maverick import record_documents

    record = record_documents.at(xa.registry_path())
    entries = json.loads(record.read_text() or "{}")
    entries[agent_id]["external_ref"] = ref
    record.write_text(json.dumps(entries))


def _stored() -> dict:
    return json.loads(watch.store_path().read_text(encoding="utf-8"))


def _platform(name: str = "fake") -> dict:
    return next(row for row in watch.status()["platforms"] if row["name"] == name)


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit_pkg
    rows: list[dict] = []

    def record(kind, *, agent="system", goal_id=None, **payload):
        rows.append({"kind": str(kind), "agent": agent, **payload})
        return True

    monkeypatch.setattr(audit_pkg, "record", record)
    return rows


@pytest.fixture
def observed(monkeypatch):
    """Calls into drift observation, captured at the hook."""
    calls: list[dict] = []

    def observe(agent_id, *, version_digest, binding_strength="", source="", now=None, description=None):
        calls.append({"agent_id": agent_id, "version_digest": version_digest,
                      "binding_strength": binding_strength, "source": source, "now": now})

    monkeypatch.setattr(drift, "observe_discovered", observe)
    return calls


# ------------------------------------------------------------------ settings

def test_settings_defaults_are_off():
    cfg = watch.settings()
    assert cfg["enable"] is False and cfg["platforms"] == [] and cfg["problems"] == []
    assert cfg["sync_minutes"] == 60 and cfg["missing_after_runs"] == 3
    assert watch.enabled() is False


def test_settings_read_the_agent_watch_section(tmp_path):
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = [" Fake ", "other", "fake"]\n'
                         "sync_minutes = 15\nmissing_after_runs = 2\nmax_agents = 40\n"
                         "max_pages = 7\ntimeout_seconds = 9\n")
    cfg = watch.settings()
    assert cfg["enable"] is True and cfg["platforms"] == ["fake", "other"]
    assert (cfg["sync_minutes"], cfg["missing_after_runs"]) == (15, 2)
    assert (cfg["max_agents"], cfg["max_pages"], cfg["timeout_seconds"]) == (40, 7, 9)
    limits = watch.limits()
    assert (limits.max_records, limits.max_pages, limits.timeout_seconds) == (40, 7, 9.0)


@pytest.mark.parametrize("line, name, expected", [
    ("sync_minutes = 0", "sync_minutes", 5),
    ("sync_minutes = 99999", "sync_minutes", 1440),
    ("missing_after_runs = 0", "missing_after_runs", 1),
    ("missing_after_runs = 500", "missing_after_runs", 30),
    ("max_agents = -4", "max_agents", 1),
    ("max_agents = 10000000", "max_agents", 20000),
    ("max_pages = 0", "max_pages", 1),
    ("max_pages = 99999", "max_pages", 1000),
    ("timeout_seconds = 0", "timeout_seconds", 2),
    ("timeout_seconds = 3600", "timeout_seconds", 120),
])
def test_settings_clamp_out_of_range_values(tmp_path, line, name, expected):
    _configure(tmp_path, f"[agent_watch]\n{line}\n")
    assert watch.settings()[name] == expected


@pytest.mark.parametrize("line, name", [
    ('sync_minutes = "hourly"', "sync_minutes"),
    ("sync_minutes = true", "sync_minutes"),
    ("sync_minutes = 7.5", "sync_minutes"),
    ("missing_after_runs = [3]", "missing_after_runs"),
    ("max_agents = nan", "max_agents"),
    ("timeout_seconds = inf", "timeout_seconds"),
    ('enable = "yes"', "enable"),
    ("enable = 1", "enable"),
])
def test_settings_fall_back_to_the_default_for_a_malformed_value(tmp_path, line, name):
    defaults = watch.settings()
    _configure(tmp_path, f"[agent_watch]\n{line}\n")
    assert watch.settings()[name] == defaults[name]


@pytest.mark.parametrize("body", ["agent_watch = 7\n", 'agent_watch = "on"\n'])
def test_a_malformed_section_turns_checks_off_and_says_so(tmp_path, body):
    _configure(tmp_path, body)
    cfg = watch.settings()
    assert cfg["enable"] is False and cfg["platforms"] == []
    assert len(cfg["problems"]) == 1 and "[agent_watch]" in cfg["problems"][0]
    assert watch.status()["problems"] == cfg["problems"]
    assert watch.sync()["ran"] is False


def test_settings_survive_a_config_loader_that_raises(monkeypatch):
    from maverick import config

    def unavailable(*_a, **_kw):
        raise RuntimeError("configuration backend unavailable")

    monkeypatch.setattr(config, "load_config", unavailable)
    cfg = watch.settings()
    assert cfg["enable"] is False and cfg["problems"]
    assert watch.enabled() is False


@pytest.mark.parametrize("line", ['platforms = "fake"', "platforms = 3", "platforms = {a = 1}"])
def test_a_platform_list_that_is_not_a_list_checks_nothing(tmp_path, line):
    _configure(tmp_path, f"[agent_watch]\nenable = true\n{line}\n")
    cfg = watch.settings()
    assert cfg["platforms"] == [] and "platforms" in cfg["problems"][0]


def test_bad_platform_names_are_skipped_and_never_echoed(tmp_path):
    _configure(tmp_path, '[agent_watch]\nenable = true\n'
                         f'platforms = ["fake", 7, "Not A Name!", "{SECRET}", "enable"]\n')
    cfg = watch.settings()
    assert cfg["platforms"] == ["fake"]
    assert len(cfg["problems"]) == 4
    assert SECRET not in json.dumps(cfg) and "Not A Name" not in json.dumps(cfg)


def test_the_number_of_platforms_is_capped(tmp_path):
    names = ", ".join(f'"p{index}"' for index in range(30))
    _configure(tmp_path, f"[agent_watch]\nplatforms = [{names}]\n")
    cfg = watch.settings()
    assert len(cfg["platforms"]) == 20 and any("20" in problem for problem in cfg["problems"])


def test_enabled_needs_outside_agent_governance(tmp_path, monkeypatch):
    _configure(tmp_path, "[agent_watch]\nenable = true\n")
    assert watch.enabled() is True
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    assert watch.enabled() is False


def test_the_environment_switch_overrides_the_setting(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_WATCH", "1")
    assert watch.enabled() is True
    _configure(tmp_path, "[agent_watch]\nenable = true\n")
    monkeypatch.setenv("MAVERICK_AGENT_WATCH", "0")
    assert watch.enabled() is False
    monkeypatch.setenv("MAVERICK_AGENT_WATCH", "maybe")
    assert watch.enabled() is True


# ------------------------------------------------- the interface and helpers

def test_fingerprint_is_stable_and_follows_the_values():
    one = watch.fingerprint({"model": "m1", "tools": ["a", "b"], "on": True, "n": None})
    assert one == watch.fingerprint({"n": None, "on": True, "tools": ["a", "b"], "model": "m1"})
    assert len(one) == 64 and int(one, 16) >= 0
    assert one != watch.fingerprint({"model": "m2", "tools": ["a", "b"], "on": True, "n": None})
    assert one != watch.fingerprint({"model": "m1", "tools": ["b", "a"], "on": True, "n": None})


@pytest.mark.parametrize("value", [object(), b"raw", {"nested": object()}, float("nan"), {1: "x"}])
def test_fingerprint_refuses_values_that_are_not_plain(value):
    with pytest.raises(TypeError):
        watch.fingerprint({"field": value})


def test_env_name_wants_a_name_and_never_echoes_what_it_was_given():
    assert watch.env_name({"key_env": "MY_SECRET_1"}, "key_env", "[agent_watch.fake]") == "MY_SECRET_1"
    for wrong in (SECRET, "", 7, None, "has space", "9LEADING"):
        with pytest.raises(watch.WatchConfigError) as refused:
            watch.env_name({"key_env": wrong}, "key_env", "[agent_watch.fake]")
        assert "key_env" in str(refused.value) and "[agent_watch.fake]" in str(refused.value)
        assert SECRET not in str(refused.value)


def test_secret_named_reads_the_variable_now_and_says_when_it_is_missing(monkeypatch):
    monkeypatch.setenv("WATCH_KEY", f" {SECRET}\n")
    assert watch.secret_named("WATCH_KEY", "key_env in [agent_watch.fake]") == SECRET
    monkeypatch.delenv("WATCH_KEY")
    with pytest.raises(watch.WatchError, match=r"key_env in \[agent_watch.fake\] is not set"):
        watch.secret_named("WATCH_KEY", "key_env in [agent_watch.fake]")


def test_secret_named_reads_a_mounted_secret_file(tmp_path, monkeypatch):
    mounted = tmp_path / "secrets"
    mounted.mkdir()
    (mounted / "WATCH_KEY").write_text(SECRET + "\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
    monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(mounted))
    assert watch.secret_named("WATCH_KEY", "key_env") == SECRET


def test_registering_needs_a_plain_name():
    watch.register("servicenow", lambda settings: FakeWatcher("servicenow", settings))
    assert "servicenow" in watch.registered()
    for wrong in ("", "Service Now", "enable", "x" * 60, 7):
        with pytest.raises(ValueError):
            watch.register(wrong, lambda settings: None)


def test_the_microsoft_checks_are_registered_out_of_the_box():
    assert {"entra_agent_id", "foundry", "copilot_studio"} <= set(watch.registered())


# ------------------------------------------------------------ guarded reads

URL = "https://platform.example/api/agents"


def _serve(monkeypatch, handler) -> list[httpx.Request]:
    """Answer every guarded request from ``handler`` instead of the network."""
    from maverick.tools import _ssrf
    requests: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    @contextmanager
    def client(url, timeout=None):
        with httpx.Client(transport=httpx.MockTransport(answer), timeout=timeout) as value:
            yield value

    monkeypatch.setattr(_ssrf, "safe_client", client)
    return requests


def _limits(**changes) -> watch.Limits:
    return watch.Limits(**{"timeout_seconds": 5.0, "max_pages": 5, "max_records": 10, **changes})


def _all(reader: watch.Reader, url: str, **how) -> list[dict]:
    """Every record of a paged list (records are read as they are asked for)."""
    return list(reader.records(url, **how))


def test_get_sends_the_bearer_and_returns_the_object(monkeypatch):
    requests = _serve(monkeypatch, lambda request: httpx.Response(200, json={"value": [1]}))
    page = watch.Reader(_limits()).get(URL, bearer=TOKEN, headers={"OData-Version": "4.0"})
    assert page == {"value": [1]}
    sent, = requests
    assert sent.method == "GET" and str(sent.url) == URL
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert sent.headers["accept"] == "application/json" and sent.headers["odata-version"] == "4.0"


@pytest.mark.parametrize("url", ["http://platform.example/api", "ftp://platform.example/x",
                                 "https://user:pw@platform.example/api", "https:///nohost", "nope"])
def test_only_plain_https_addresses_are_read(monkeypatch, url):
    requests = _serve(monkeypatch, lambda request: httpx.Response(200, json={}))
    with pytest.raises(watch.WatchError):
        watch.Reader(_limits()).get(url, bearer=TOKEN)
    assert requests == []


def test_an_address_the_outbound_guard_refuses_is_a_plain_error():
    # No stand-in here: the real guard resolves the name and refuses a private address.
    with pytest.raises(watch.WatchError, match="not allowed|could not be found"):
        watch.Reader(_limits()).get("https://127.0.0.1/api", bearer=TOKEN)


def _resolving_to(monkeypatch, address: str) -> list[httpx.Request]:
    """Run the real outbound guard: the name resolves to ``address`` and only
    the last hop, the socket, is replaced."""
    import socket
    wire: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        wire.append(request)
        return httpx.Response(200, json={"value": []})

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))])
    monkeypatch.setattr(httpx, "HTTPTransport", lambda *a, **k: httpx.MockTransport(answer))
    return wire


def test_a_read_goes_through_the_real_guard_pinned_to_the_address_it_checked(monkeypatch):
    wire = _resolving_to(monkeypatch, "93.184.216.34")
    assert watch.Reader(_limits()).get(URL, bearer=TOKEN) == {"value": []}
    sent, = wire
    assert sent.url.host == "93.184.216.34" and sent.headers["host"] == "platform.example"
    assert sent.extensions["sni_hostname"] == "platform.example"
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("address", ["10.0.0.5", "169.254.169.254", "127.0.0.1", "100.100.100.200"])
def test_a_name_that_resolves_inside_the_network_is_never_contacted(monkeypatch, address):
    wire = _resolving_to(monkeypatch, address)
    with pytest.raises(watch.WatchError, match="not allowed"):
        watch.Reader(_limits()).get(URL, bearer=TOKEN)
    with pytest.raises(watch.WatchError, match="not allowed"):
        watch.client_credentials_token(TOKEN_URL, client_id="c", client_secret=SECRET, scope="s")
    assert wire == []


@pytest.mark.parametrize("status, words", [
    (401, "sign-in"), (403, "permission"), (404, "address"), (429, "limiting"),
    (302, "redirect"), (500, "HTTP 500"), (204, "HTTP 204")])
def test_an_error_answer_is_put_in_plain_words_without_its_body(monkeypatch, status, words):
    body = {"error": {"message": f"token {TOKEN} was rejected"}}
    _serve(monkeypatch, lambda request: httpx.Response(status, json=body,
                                                      headers={"Location": "https://evil.example/"}))
    with pytest.raises(watch.WatchError) as failed:
        watch.Reader(_limits()).get(URL, bearer=TOKEN)
    assert words in str(failed.value) and TOKEN not in str(failed.value)


def test_a_redirect_is_never_followed(monkeypatch):
    requests = _serve(monkeypatch, lambda request: httpx.Response(
        302, headers={"Location": "https://elsewhere.example/steal"}))
    with pytest.raises(watch.WatchError, match="redirect"):
        watch.Reader(_limits()).get(URL, bearer=TOKEN)
    assert [request.url.host for request in requests] == ["platform.example"]


def test_an_answer_larger_than_the_bound_is_an_error_and_is_not_read_to_the_end(monkeypatch):
    pulled: list[int] = []

    class Endless(httpx.SyncByteStream):
        def __iter__(self):
            for index in range(10_000):
                pulled.append(index)
                yield b" " * 65536

    _serve(monkeypatch, lambda request: httpx.Response(200, stream=Endless()))
    with pytest.raises(watch.WatchError, match="larger"):
        watch.Reader(_limits(max_response_bytes=200_000)).get(URL, bearer=TOKEN)
    assert len(pulled) <= 5


@pytest.mark.parametrize("content", [b"{ not json", b"[1, 2]", b'"text"', b"", b"\xff\xfe"])
def test_an_answer_that_is_not_a_json_object_is_an_error(monkeypatch, content):
    _serve(monkeypatch, lambda request: httpx.Response(200, content=content))
    with pytest.raises(watch.WatchError, match="expected form"):
        watch.Reader(_limits()).get(URL, bearer=TOKEN)


@pytest.mark.parametrize("failure, words", [
    (httpx.ConnectTimeout("slow"), "in time"), (httpx.ReadTimeout("slow"), "in time"),
    (httpx.ConnectError(f"boom {TOKEN}"), "could not be reached")])
def test_network_failures_are_plain_errors(monkeypatch, failure, words):
    def handler(request):
        raise failure

    _serve(monkeypatch, handler)
    with pytest.raises(watch.WatchError) as failed:
        watch.Reader(_limits()).get(URL, bearer=TOKEN)
    assert words in str(failed.value) and TOKEN not in str(failed.value)


def test_an_answer_that_trickles_in_stops_at_the_timeout(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(watch, "_monotonic", lambda: clock[0])

    def trickle():
        for _ in range(10_000):
            clock[0] += 2.0
            yield b" "

    _serve(monkeypatch, lambda request: httpx.Response(200, content=trickle()))
    with pytest.raises(watch.WatchError, match="in time"):
        watch.Reader(_limits(timeout_seconds=5.0)).get(URL, bearer=TOKEN)


def test_blocked_outbound_traffic_is_a_plain_error(monkeypatch):
    from maverick import enterprise
    from maverick.tools import _ssrf

    def blocked(url, timeout=None):
        raise enterprise.EgressBlocked("platform.example")

    monkeypatch.setattr(_ssrf, "safe_client", blocked)
    with pytest.raises(watch.WatchError, match="network rules"):
        watch.Reader(_limits()).get(URL, bearer=TOKEN)


def _paged(pages: dict[str, dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[str(request.url)])
    return handler


def test_pages_follow_the_next_link_to_the_end(monkeypatch):
    requests = _serve(monkeypatch, _paged({
        URL: {"value": [{"id": "a"}, {"id": "b"}], "@odata.nextLink": URL + "?$skiptoken=X1"},
        URL + "?$skiptoken=X1": {"value": [], "@odata.nextLink": URL + "?$skiptoken=X2"},
        URL + "?$skiptoken=X2": {"value": [{"id": "c"}]}}))
    rows = _all(watch.Reader(_limits()), URL, bearer=TOKEN, items="value", next_url=watch.odata_next)
    assert [row["id"] for row in rows] == ["a", "b", "c"]
    assert [request.method for request in requests] == ["GET"] * 3
    assert all(request.headers["authorization"] == f"Bearer {TOKEN}" for request in requests)


def test_records_are_read_a_page_at_a_time_as_they_are_asked_for(monkeypatch):
    requests = _serve(monkeypatch, _paged({
        URL: {"value": [{"id": "a"}, {"id": "b"}], "@odata.nextLink": URL + "?p=2"},
        URL + "?p=2": {"value": [{"id": "c"}]}}))
    records = watch.Reader(_limits()).records(URL, bearer=TOKEN, items="value", next_url=watch.odata_next)
    assert requests == []
    assert next(records) == {"id": "a"} and len(requests) == 1
    assert [row["id"] for row in records] == ["b", "c"] and len(requests) == 2


def test_a_next_link_is_used_exactly_as_given(monkeypatch):
    cookie = ("?$select=name&$skiptoken=%3Ccookie%20pagenumber=%222%22%20pagingcookie=%22%253ccookie"
              "%2520page%253d%25221%2522%253e%22%20istracking=%22False%22%20/%3E")
    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.raw_path)
        if b"skiptoken" in request.url.raw_path:
            return httpx.Response(200, json={"value": [{"id": "b"}]})
        return httpx.Response(200, json={"value": [{"id": "a"}], "@odata.nextLink": URL + cookie})

    _serve(monkeypatch, handler)
    rows = _all(watch.Reader(_limits()), URL + "?$select=name", bearer=TOKEN, items="value",
                next_url=watch.odata_next)
    assert len(rows) == 2 and sent[1] == ("/api/agents" + cookie).encode("ascii")


def test_a_list_longer_than_the_page_cap_is_an_error_not_a_short_list(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "0"))
        return httpx.Response(200, json={"value": [{"id": page}],
                                         "@odata.nextLink": f"{URL}?page={page + 1}"})

    requests = _serve(monkeypatch, handler)
    with pytest.raises(watch.WatchError, match="3 pages"):
        _all(watch.Reader(_limits(max_pages=3, max_records=1000)), URL, bearer=TOKEN, items="value",
             next_url=watch.odata_next)
    assert len(requests) == 3


def test_more_records_than_the_cap_is_an_error_not_a_short_list(monkeypatch):
    _serve(monkeypatch, _paged({
        URL: {"value": [{"id": n} for n in range(6)], "@odata.nextLink": URL + "?p=2"},
        URL + "?p=2": {"value": [{"id": n} for n in range(6)]}}))
    with pytest.raises(watch.WatchError, match="more than 10"):
        _all(watch.Reader(_limits()), URL, bearer=TOKEN, items="value", next_url=watch.odata_next)


def test_the_caps_cover_everything_one_run_reads(monkeypatch):
    _serve(monkeypatch, lambda request: httpx.Response(200, json={"value": [{"id": 1}] * 4}))
    reader = watch.Reader(_limits(max_records=10))
    for _ in range(2):
        _all(reader, URL, bearer=TOKEN, items="value", next_url=watch.odata_next)
    with pytest.raises(watch.WatchError, match="more than 10"):
        _all(reader, URL, bearer=TOKEN, items="value", next_url=watch.odata_next)


def test_a_next_link_that_repeats_is_a_loop_and_an_error(monkeypatch):
    requests = _serve(monkeypatch, _paged({
        URL: {"value": [{"id": "a"}], "@odata.nextLink": URL + "?p=2"},
        URL + "?p=2": {"value": [{"id": "b"}], "@odata.nextLink": URL}}))
    with pytest.raises(watch.WatchError, match="repeat"):
        _all(watch.Reader(_limits()), URL, bearer=TOKEN, items="value", next_url=watch.odata_next)
    assert len(requests) == 2


@pytest.mark.parametrize("page", [
    {"value": "not a list"}, {"value": [{"id": "a"}, "junk"]}, {"items": []}, {"value": None}])
def test_a_malformed_page_is_an_error(monkeypatch, page):
    _serve(monkeypatch, lambda request: httpx.Response(200, json=page))
    with pytest.raises(watch.WatchError, match="expected form"):
        _all(watch.Reader(_limits()), URL, bearer=TOKEN, items="value", next_url=watch.odata_next)


@pytest.mark.parametrize("link", [
    "https://evil.example/api/agents?$skiptoken=1",
    "http://platform.example/api/agents?$skiptoken=1",
    "https://platform.example:8443/api/agents?$skiptoken=1",
    "https://platform.example/api/users?$skiptoken=1",
    "https://user:pw@platform.example/api/agents?$skiptoken=1",
    "https://platform.example.evil.example/api/agents",
    "/api/agents?$skiptoken=1", "", 7, ["https://platform.example/api/agents"],
    "https://platform.example/api/agents?x=" + "y" * 20_000])
def test_a_next_link_that_leaves_the_address_being_read_is_an_error(monkeypatch, link):
    requests = _serve(monkeypatch, lambda request: httpx.Response(
        200, json={"value": [{"id": "a"}], "@odata.nextLink": link}))
    with pytest.raises(watch.WatchError):
        _all(watch.Reader(_limits()), URL, bearer=TOKEN, items="value", next_url=watch.odata_next)
    assert [request.url.host for request in requests] == ["platform.example"]


def test_a_next_link_may_differ_in_letter_case_only(monkeypatch):
    _serve(monkeypatch, _paged({
        URL: {"value": [{"id": "a"}], "@odata.nextLink": "https://PLATFORM.example/API/Agents?p=2"},
        "https://platform.example/API/Agents?p=2": {"value": [{"id": "b"}]}}))
    rows = _all(watch.Reader(_limits()), URL, bearer=TOKEN, items="value", next_url=watch.odata_next)
    assert len(rows) == 2


def test_one_run_has_one_overall_time_limit(monkeypatch):
    clock = [50.0]
    monkeypatch.setattr(watch, "_monotonic", lambda: clock[0])

    def handler(request: httpx.Request) -> httpx.Response:
        clock[0] += 40.0
        page = int(request.url.params.get("page", "0"))
        return httpx.Response(200, json={"value": [], "@odata.nextLink": f"{URL}?page={page + 1}"})

    requests = _serve(monkeypatch, handler)
    with pytest.raises(watch.WatchError, match="in time"):
        _all(watch.Reader(_limits(max_pages=100, timeout_seconds=60.0, run_seconds=100.0)), URL,
             bearer=TOKEN, items="value", next_url=watch.odata_next)
    assert len(requests) == 3


# ----------------------------------------------------------------- sign-in

TOKEN_URL = "https://login.example/tenant-1/oauth2/v2.0/token"


class ExampleWatcher:
    """A whole watcher built from the shared helpers, the way a real platform
    module is written: check the settings in the constructor (no network, no
    secret read), then in ``list_agents`` read the secret by name, sign in,
    page through the platform's fixed list address and turn each row into an
    ``ObservedAgent``. Any failure is a ``WatchError``; the helpers raise it."""

    name = "example"

    def __init__(self, settings: dict) -> None:
        section = "[agent_watch.example]"
        self._client_id = watch.env_name(settings, "client_id_env", section)
        self._secret = watch.env_name(settings, "client_secret_env", section)

    def list_agents(self) -> list[watch.ObservedAgent]:
        token = watch.client_credentials_token(
            TOKEN_URL, scope="agents.read",
            client_id=watch.secret_named(self._client_id, "client_id_env in [agent_watch.example]"),
            client_secret=watch.secret_named(self._secret, "client_secret_env in [agent_watch.example]"))
        rows = watch.Reader().records(URL, bearer=token, items="value", next_url=watch.odata_next)
        return [self._agent(row) for row in rows]

    def _agent(self, row: dict) -> watch.ObservedAgent:
        if not isinstance(row.get("id"), str) or not isinstance(row.get("model"), str):
            raise watch.unexpected_answer()
        return watch.ObservedAgent(
            platform=self.name, external_id=row["id"], name=str(row.get("label") or ""),
            state="enabled" if row.get("active") is True else "disabled",
            fingerprint=watch.fingerprint({"model": row["model"], "active": row.get("active")}))


def test_a_watcher_built_from_the_shared_helpers_end_to_end(tmp_path, monkeypatch, observed):
    watch.register("example", ExampleWatcher)
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = ["example"]\n'
                         '[agent_watch.example]\nclient_id_env = "EXAMPLE_ID"\n'
                         'client_secret_env = "EXAMPLE_SECRET"\n')
    monkeypatch.setenv("EXAMPLE_ID", "client-1")
    monkeypatch.setenv("EXAMPLE_SECRET", SECRET)
    _enroll(ref="example:agent-a")

    def platform(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3600,
                                             "access_token": TOKEN})
        if "skiptoken" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "agent-b", "model": "m2", "active": False}]})
        return httpx.Response(200, json={"value": [{"id": "agent-a", "model": "m1", "active": True,
                                                    "label": "Agent A"}],
                                         "@odata.nextLink": URL + "?$skiptoken=2"})

    requests = _serve(monkeypatch, platform)
    summary = watch.sync(now=T0)
    assert summary["platforms"]["example"] == {"ok": True, "error": "", "listed": 2, "matched": 1,
                                               "not_enrolled": 1, "missing": 0}
    assert [request.method for request in requests] == ["POST", "GET", "GET"]
    assert observed[0]["version_digest"] == watch.fingerprint({"model": "m1", "active": True})
    assert watch.unenrolled()[0]["external_ref"] == "example:agent-b"
    monkeypatch.delenv("EXAMPLE_SECRET")
    watch._TOKENS.clear()
    assert "client_secret_env in [agent_watch.example] is not set" in \
        watch.sync(now=T0 + 60)["platforms"]["example"]["error"]


def _token_service(monkeypatch, *, expires_in=3599, status=200, body=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if status != 200 or body is not None:
            return httpx.Response(status, json=body if body is not None else {})
        return httpx.Response(200, json={"token_type": "Bearer", "expires_in": expires_in,
                                         "access_token": TOKEN})
    return _serve(monkeypatch, handler)


def _sign_in(scope: str = "https://api.example/.default") -> str:
    return watch.client_credentials_token(TOKEN_URL, client_id="client-1",
                                          client_secret=SECRET, scope=scope)


def test_sign_in_posts_the_client_credentials_form(monkeypatch):
    requests = _token_service(monkeypatch)
    assert _sign_in() == TOKEN
    sent, = requests
    assert sent.method == "POST" and str(sent.url) == TOKEN_URL
    assert sent.headers["content-type"] == "application/x-www-form-urlencoded"
    form = dict(httpx.QueryParams(sent.content.decode("ascii")))
    assert form == {"grant_type": "client_credentials", "client_id": "client-1",
                    "client_secret": SECRET, "scope": "https://api.example/.default"}
    assert SECRET not in str(sent.url)


def test_a_token_is_kept_in_memory_until_shortly_before_it_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(watch, "_monotonic", lambda: clock[0])
    requests = _token_service(monkeypatch, expires_in=3600)
    assert _sign_in() == TOKEN and _sign_in() == TOKEN
    assert len(requests) == 1
    clock[0] += 3600 - 121  # still inside its life, less the safety margin
    _sign_in()
    assert len(requests) == 1
    clock[0] += 2  # past the margin: sign in again
    _sign_in()
    assert len(requests) == 2


def test_tokens_are_kept_per_scope_and_client(monkeypatch):
    requests = _token_service(monkeypatch)
    _sign_in("https://one.example/.default")
    _sign_in("https://two.example/.default")
    _sign_in("https://one.example/.default")
    assert len(requests) == 2


def test_a_token_too_short_lived_to_keep_is_not_kept(monkeypatch):
    requests = _token_service(monkeypatch, expires_in=60)
    _sign_in()
    _sign_in()
    assert len(requests) == 2


def test_the_token_table_is_bounded(monkeypatch):
    _token_service(monkeypatch)
    for index in range(80):
        _sign_in(f"https://api{index}.example/.default")
    assert len(watch._TOKENS) <= 32


def test_a_rejected_token_is_forgotten_so_the_next_run_signs_in_again(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3600,
                                             "access_token": TOKEN})
        return httpx.Response(401, json={"error": "expired"})

    requests = _serve(monkeypatch, handler)
    token = _sign_in()
    with pytest.raises(watch.WatchError, match="sign-in"):
        watch.Reader(_limits()).get(URL, bearer=token)
    _sign_in()
    assert [request.method for request in requests] == ["POST", "GET", "POST"]


def test_a_refused_sign_in_gives_the_short_reason_and_nothing_else(monkeypatch):
    _token_service(monkeypatch, status=401, body={
        "error": "invalid_client",
        "error_description": f"AADSTS7000215: Invalid client secret provided: {SECRET}. Trace ID: 0000",
        "error_codes": [7000215], "trace_id": "0000aaaa", "correlation_id": "aaaa0000"})
    with pytest.raises(watch.WatchError) as refused:
        _sign_in()
    text = str(refused.value)
    assert "invalid_client" in text and "client secret" in text
    assert SECRET not in text and "AADSTS" not in text and "0000aaaa" not in text
    assert watch._TOKENS == {}


@pytest.mark.parametrize("body", [
    {"token_type": "Bearer", "expires_in": 3600},
    {"token_type": "Bearer", "expires_in": 3600, "access_token": ""},
    {"token_type": "Bearer", "expires_in": 3600, "access_token": 7},
    {"token_type": "mac", "expires_in": 3600, "access_token": TOKEN},
    {"token_type": "Bearer", "expires_in": 3600, "access_token": "two words"}])
def test_a_sign_in_answer_without_a_usable_token_is_an_error(monkeypatch, body):
    _token_service(monkeypatch, body=body)
    with pytest.raises(watch.WatchError, match="sign-in"):
        _sign_in()
    assert watch._TOKENS == {}


@pytest.mark.parametrize("expires_in", [None, "soon", -5, 0, True, [3600]])
def test_a_token_with_no_usable_lifetime_is_used_once_and_not_kept(monkeypatch, expires_in):
    requests = _token_service(monkeypatch, body={"token_type": "bearer", "expires_in": expires_in,
                                                 "access_token": TOKEN})
    assert _sign_in() == TOKEN and _sign_in() == TOKEN
    assert len(requests) == 2


def test_sign_in_only_goes_to_https(monkeypatch):
    requests = _token_service(monkeypatch)
    with pytest.raises(watch.WatchError):
        watch.client_credentials_token("http://login.example/token", client_id="c",
                                       client_secret=SECRET, scope="s")
    assert requests == []


# ------------------------------------------------ matching and drift observation

def test_a_listed_agent_is_matched_through_its_external_ref(fake, observed, audit_rows):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1", strong=True), _seen("bot-2")]
    summary = watch.sync(now=T0)
    assert summary["ran"] is True
    assert summary["platforms"]["fake"] == {"ok": True, "error": "", "listed": 2, "matched": 1,
                                            "not_enrolled": 1, "missing": 0}
    call, = observed
    assert call == {"agent_id": AGENT, "version_digest": watch.fingerprint({"config": "v1"}),
                    "binding_strength": "immutable_provider_revision", "source": "fake", "now": T0}
    view = watch.platform_view(AGENT)
    assert view["listed"] is True and view["missing_on_platform"] is False
    assert (view["state"], view["version"], view["updated_at"]) == ("enabled", "1", "2026-11-01T10:00:00Z")
    assert (view["platform"], view["external_id"], view["last_seen_at"]) == ("fake", "bot-1", T0)


def test_a_changed_fingerprint_becomes_a_drift_finding_from_the_authoritative_source(fake):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1", config="v1")]
    watch.sync(now=T0)
    drift.approve_baseline(AGENT, actor="dana@corp.test", force=True, now=T0 + 60)
    watch.sync(now=T0 + 3600)
    assert "config_changed" not in {f["kind"] for f in drift.evaluate(AGENT, now=T0 + 3700)["findings"]}

    fake.agents["fake"] = [_seen("bot-1", config="v2")]
    watch.sync(now=T0 + 7200)
    result = drift.evaluate(AGENT, now=T0 + 7300)
    finding, = [f for f in result["findings"] if f["kind"] == "config_changed"]
    assert (finding["severity"], finding["source"]) == ("high", "discovery")
    assert finding["baseline"] == watch.fingerprint({"config": "v1"})
    assert finding["current"] == watch.fingerprint({"config": "v2"})
    assert result["state"] == "drifted"
    seen = drift.detail(AGENT, now=T0 + 7300)["config"]["discovered"]
    assert (seen["source"], seen["binding_strength"]) == ("fake", "observed_snapshot")


def test_checks_still_run_while_drift_detection_is_off(fake, monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_DRIFT", "0")
    _enroll()
    fake.agents["fake"] = [_seen("bot-1"), _seen("bot-2")]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["matched"] == 1
    assert watch.platform_view(AGENT)["listed"] is True and len(watch.unenrolled()) == 1
    assert not drift.store_path().exists()


def test_matching_ignores_letter_case_and_surrounding_space(fake, observed):
    _enroll(ref="  Fake:BOT-1 ")
    fake.agents["fake"] = [_seen("bot-1")]
    assert watch.sync(now=T0)["platforms"]["fake"]["matched"] == 1
    assert [call["agent_id"] for call in observed] == [AGENT]
    assert watch.unenrolled() == []


@pytest.mark.parametrize("ref", [None, "", "bot-1", ":bot-1", "fake:", 7, ["fake:bot-1"],
                                 {"platform": "fake"}, "fake:has space", "Not A Platform:bot-1"])
def test_an_agent_without_a_usable_external_ref_is_simply_not_matched(fake, observed, ref):
    _enroll(ref=ref)
    fake.agents["fake"] = [_seen("bot-1")]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["matched"] == 0 and observed == []
    assert watch.platform_view(AGENT) is None
    assert [row["external_id"] for row in watch.unenrolled()] == ["bot-1"]


def test_two_agents_enrolled_against_the_same_platform_agent_are_both_matched(fake, observed):
    _enroll("one")
    _enroll("two")
    fake.agents["fake"] = [_seen("bot-1")]
    assert watch.sync(now=T0)["platforms"]["fake"]["matched"] == 2
    assert sorted(call["agent_id"] for call in observed) == ["one", "two"]


def test_an_agent_on_a_platform_that_is_not_checked_is_left_alone(fake, observed):
    _enroll(ref="servicenow:bot-1")
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    view = watch.platform_view(AGENT)
    assert view["watched"] is False and view["checked"] is False
    assert view["listed"] is None and view["missing_on_platform"] is False
    assert observed == []


def test_platform_view_before_any_check_and_for_unknown_agents(fake):
    _enroll()
    view = watch.platform_view(AGENT)
    assert view["watched"] is True and view["checked"] is False and view["listed"] is None
    assert watch.platform_view("nobody") is None


# ------------------------------------------------------------ not enrolled

def test_agents_that_were_never_enrolled_are_listed_with_first_and_last_seen(fake):
    fake.agents["fake"] = [_seen("bot-9", name="Payroll helper", state="disabled", version="4")]
    watch.sync(now=T0)
    watch.sync(now=T0 + 3600)
    row, = watch.unenrolled()
    assert row == {"platform": "fake", "external_id": "bot-9", "external_ref": "fake:bot-9",
                   "name": "Payroll helper", "state": "disabled", "version": "4",
                   "updated_at": "2026-11-01T10:00:00Z",
                   "first_seen_at": T0, "last_seen_at": T0 + 3600}
    assert watch.status()["not_enrolled_count"] == 1


def test_an_agent_leaves_the_list_when_it_is_enrolled_or_gone(fake):
    fake.agents["fake"] = [_seen("bot-1"), _seen("bot-2"), _seen("bot-3")]
    watch.sync(now=T0)
    assert len(watch.unenrolled()) == 3
    _enroll(ref="fake:bot-1")
    fake.agents["fake"] = [_seen("bot-1"), _seen("bot-2")]
    watch.sync(now=T0 + 60)
    assert [row["external_id"] for row in watch.unenrolled()] == ["bot-2"]


def test_the_not_enrolled_list_is_bounded_and_says_how_many_there_really_are(fake, monkeypatch):
    monkeypatch.setattr(watch, "_MAX_UNENROLLED", 5)
    fake.agents["fake"] = [_seen(f"bot-{index:02d}") for index in range(12)]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["not_enrolled"] == 12
    assert len(watch.unenrolled()) == 5
    row = _platform()
    assert (row["not_enrolled"], row["not_enrolled_shown"]) == (12, 5)
    # The ones kept are the ones already known, so the list does not churn.
    kept = {row["external_id"] for row in watch.unenrolled()}
    fake.agents["fake"] = list(reversed(fake.agents["fake"]))
    watch.sync(now=T0 + 60)
    assert {row["external_id"] for row in watch.unenrolled()} == kept


def test_names_from_a_platform_are_bounded_and_secrets_in_them_are_dropped(fake):
    fake.agents["fake"] = [
        _seen("bot-1", name="x" * 5000),
        _seen("bot-2", name=f"helper {TOKEN}"),
        _seen("bot-3", name="tab\tand\x00null\nnewline"),
    ]
    watch.sync(now=T0)
    names = {row["external_id"]: row["name"] for row in watch.unenrolled()}
    assert len(names["bot-1"]) <= 120 and names["bot-2"] == ""
    assert names["bot-3"] == "tab andnull newline"
    assert TOKEN not in watch.store_path().read_text(encoding="utf-8")


# -------------------------------------------------------- missing on platform

def test_an_agent_absent_for_enough_runs_is_marked_missing_and_reset_when_it_returns(fake, tmp_path):
    _configure(tmp_path, _WATCHING.format(extra="missing_after_runs = 2"))
    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    fake.agents["fake"] = []
    first = watch.sync(now=T0 + 100)
    view = watch.platform_view(AGENT)
    assert (view["listed"], view["missing_runs"], view["missing_on_platform"]) == (False, 1, False)
    assert first["platforms"]["fake"]["missing"] == 0 and view["last_seen_at"] == T0

    second = watch.sync(now=T0 + 200)
    view = watch.platform_view(AGENT)
    assert (view["missing_runs"], view["missing_on_platform"], view["missing_since"]) == (2, True, T0 + 200)
    assert second["platforms"]["fake"]["missing"] == 1 and second["missing_on_platform"] == 1
    assert watch.status()["missing_count"] == 1
    watch.sync(now=T0 + 300)
    assert watch.platform_view(AGENT)["missing_since"] == T0 + 200  # when it began, not the latest run

    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0 + 400)
    view = watch.platform_view(AGENT)
    assert (view["listed"], view["missing_runs"], view["missing_on_platform"]) == (True, 0, False)
    assert view["missing_since"] is None and watch.status()["missing_count"] == 0


def test_a_failed_run_does_not_count_towards_missing(fake, tmp_path):
    _configure(tmp_path, _WATCHING.format(extra="missing_after_runs = 2"))
    _enroll()
    fake.agents["fake"] = []
    watch.sync(now=T0)
    fake.failure["fake"] = watch.WatchError("The platform did not answer in time.")
    for step in range(1, 5):
        watch.sync(now=T0 + step)
    view = watch.platform_view(AGENT)
    assert (view["missing_runs"], view["missing_on_platform"]) == (1, False)


def test_an_agent_never_seen_on_its_platform_becomes_missing_too(fake, observed):
    _enroll(ref="fake:typo")
    fake.agents["fake"] = [_seen("bot-1")]
    for step in range(3):
        watch.sync(now=T0 + step)
    view = watch.platform_view(AGENT)
    assert view["missing_on_platform"] is True and view["last_seen_at"] is None
    assert observed == []


def test_changing_an_agents_external_ref_starts_its_view_again(fake, tmp_path):
    _configure(tmp_path, _WATCHING.format(extra="missing_after_runs = 1"))
    _enroll(ref="fake:gone")
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    assert watch.platform_view(AGENT)["missing_on_platform"] is True
    _set_ref(AGENT, "fake:bot-1")
    assert watch.platform_view(AGENT)["checked"] is False  # the old answer was about another agent
    watch.sync(now=T0 + 60)
    view = watch.platform_view(AGENT)
    assert (view["listed"], view["missing_on_platform"], view["missing_runs"]) == (True, False, 0)


def test_an_unenrolled_agents_view_is_dropped(fake):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    assert AGENT in _stored()["agents"]
    xa.unenroll(AGENT)
    watch.sync(now=T0 + 60)
    assert _stored()["agents"] == {}
    assert [row["external_id"] for row in watch.unenrolled()] == ["bot-1"]


# --------------------------------------------------- one platform failing

def test_one_platform_failing_does_not_stop_another_or_wipe_what_was_known(tmp_path, observed):
    _two_platforms(tmp_path)
    _enroll("on-fake", ref="fake:bot-1")
    _enroll("on-other", ref="other:bot-7")
    FakeWatcher.agents = {"fake": [_seen("bot-1"), _seen("bot-2")],
                          "other": [_seen("bot-7", platform="other"), _seen("bot-8", platform="other")]}
    watch.sync(now=T0)
    observed.clear()
    before = {name: _stored()[name].get("fake") for name in ("platforms", "unenrolled")}
    before_view = watch.platform_view("on-fake")

    FakeWatcher.failure["fake"] = watch.WatchError("The platform refused this check (HTTP 403).")
    summary = watch.sync(now=T0 + 3600)
    assert summary["platforms"]["fake"] == {"ok": False, "error": "The platform refused this check (HTTP 403)."}
    assert summary["platforms"]["other"]["ok"] is True
    assert (summary["succeeded"], summary["failed"]) == (1, 1)
    assert [call["agent_id"] for call in observed] == ["on-other"]

    row = _platform("fake")
    assert row["last_error"] == "The platform refused this check (HTTP 403)."
    assert (row["last_attempt_at"], row["last_error_at"], row["last_success_at"]) == (T0 + 3600, T0 + 3600, T0)
    assert (row["failures_in_a_row"], row["listed"], row["not_enrolled"]) == (1, 2, 1)
    assert _stored()["unenrolled"]["fake"] == before["unenrolled"]
    assert watch.platform_view("on-fake") == before_view
    assert {r["external_ref"] for r in watch.unenrolled()} == {"fake:bot-2", "other:bot-8"}

    watch.sync(now=T0 + 7200)
    assert _platform("fake")["failures_in_a_row"] == 2
    del FakeWatcher.failure["fake"]
    watch.sync(now=T0 + 9000)
    row = _platform("fake")
    assert (row["last_error"], row["last_error_at"], row["failures_in_a_row"]) == ("", None, 0)
    assert row["last_success_at"] == T0 + 9000


def test_an_unexpected_failure_is_reported_without_its_text(fake, caplog):
    fake.failure["fake"] = RuntimeError(f"boom {SECRET} {TOKEN}")
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    error = summary["platforms"]["fake"]["error"]
    assert summary["platforms"]["fake"]["ok"] is False and "unexpected" in error
    everything = json.dumps(summary) + json.dumps(watch.status()) + caplog.text \
        + watch.store_path().read_text(encoding="utf-8")
    assert SECRET not in everything and TOKEN not in everything
    assert "RuntimeError" in caplog.text


def test_a_watcher_error_is_redacted_and_bounded_before_it_is_kept(fake, caplog):
    fake.failure["fake"] = watch.WatchError(f"The platform said: Bearer {TOKEN} " + "x" * 2000)
    with caplog.at_level(logging.DEBUG):
        summary = watch.sync(now=T0)
    error = summary["platforms"]["fake"]["error"]
    assert error.startswith("The platform said: Bearer") and len(error) <= 300
    everything = json.dumps(summary) + json.dumps(watch.status()) + caplog.text \
        + watch.store_path().read_text(encoding="utf-8")
    assert TOKEN not in everything


@pytest.mark.parametrize("answer", [
    None, "agents", [{"external_id": "bot-1"}], ["bot-1"],
    [watch.ObservedAgent(platform="elsewhere", external_id="bot-1", fingerprint="0" * 64)],
    [watch.ObservedAgent(platform="fake", external_id="", fingerprint="0" * 64)],
    [watch.ObservedAgent(platform="fake", external_id="has space", fingerprint="0" * 64)],
    [watch.ObservedAgent(platform="fake", external_id="x" * 300, fingerprint="0" * 64)],
    [watch.ObservedAgent(platform="fake", external_id="bot-1", fingerprint="not-a-digest")],
    [watch.ObservedAgent(platform="fake", external_id="bot-1", fingerprint="0" * 64, state="paused")],
    [watch.ObservedAgent(platform="fake", external_id="bot-1", fingerprint="0" * 64,
                         binding_strength="trust me")],
    [watch.ObservedAgent(platform="fake", external_id=7, fingerprint="0" * 64)],
])
def test_a_watcher_that_returns_something_unusable_fails_its_run(fake, observed, monkeypatch, answer):
    _enroll()
    monkeypatch.setattr(FakeWatcher, "list_agents", lambda self: answer)
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["ok"] is False and observed == []
    assert watch.unenrolled() == []


def test_the_same_agent_listed_twice_counts_once(fake, observed):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1"), _seen("bot-1"), _seen("bot-2"), _seen("bot-2")]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["listed"] == 2 and len(observed) == 1
    assert len(watch.unenrolled()) == 1


def test_two_ids_that_differ_only_in_letter_case_fail_the_run_instead_of_losing_one(fake, observed):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1"), _seen("BOT-1")]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["ok"] is False
    assert "capital and small letters" in summary["platforms"]["fake"]["error"] and observed == []


def test_a_watcher_that_lists_more_than_the_cap_fails_its_run(fake, tmp_path):
    _configure(tmp_path, _WATCHING.format(extra="max_agents = 3"))
    fake.agents["fake"] = [_seen(f"bot-{index}") for index in range(4)]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["ok"] is False and "more than 3" in summary["platforms"]["fake"]["error"]
    assert watch.unenrolled() == []


# ------------------------------------------------------- malformed settings

def test_a_platform_with_no_check_is_reported_and_the_rest_still_run(tmp_path, observed):
    watch.register("fake", lambda settings: FakeWatcher("fake", settings))
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = ["workday", "fake"]\n'
                         '[agent_watch.fake]\nsite = "one"\n')
    _enroll()
    FakeWatcher.agents["fake"] = [_seen("bot-1")]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["workday"]["ok"] is False
    assert "workday" in summary["platforms"]["workday"]["error"]
    assert summary["platforms"]["fake"]["matched"] == 1
    row = _platform("workday")
    assert row["ready"] is False and "workday" in row["problem"]
    assert _platform("fake")["ready"] is True and _platform("fake")["problem"] == ""


@pytest.mark.parametrize("table", ['fake = "one"', "fake = 7", "fake = [1, 2]",
                                   "[agent_watch.fake]\nsite = 7", "[agent_watch.fake]"])
def test_a_malformed_platform_section_disables_that_platform_only(tmp_path, table):
    _two_platforms(tmp_path)
    body = (tmp_path / "config.toml").read_text(encoding="utf-8")
    head, _, tail = body.partition('[agent_watch.fake]\nsite = "one"\n')
    if table.startswith("["):
        _configure(tmp_path, head + table + "\n" + tail)
    else:
        _configure(tmp_path, head.rstrip("\n") + "\n" + table + "\n" + tail)
    FakeWatcher.agents["other"] = [_seen("bot-7", platform="other")]
    row = _platform("fake")
    assert row["ready"] is False and "[agent_watch.fake]" in row["problem"]
    summary = watch.sync(now=T0)
    assert summary["platforms"]["fake"]["ok"] is False and summary["platforms"]["other"]["ok"] is True
    assert FakeWatcher.calls == ["other"]
    assert _platform("fake")["last_error"] == row["problem"]


def test_a_factory_that_blows_up_is_a_settings_problem_not_a_crash(tmp_path):
    def broken(settings):
        raise KeyError(SECRET)

    watch.register("fake", broken)
    _configure(tmp_path, _WATCHING.format(extra=""))
    row = _platform()
    assert row["ready"] is False and "[agent_watch.fake]" in row["problem"]
    assert SECRET not in json.dumps(watch.status())
    assert watch.sync(now=T0)["platforms"]["fake"]["ok"] is False


def test_a_factory_gets_its_own_copy_of_its_table(tmp_path):
    received: list[dict] = []

    def factory(settings):
        received.append(dict(settings))
        settings["site"] = "changed"
        return FakeWatcher("fake", settings)

    watch.register("fake", factory)
    _configure(tmp_path, _WATCHING.format(extra=""))
    watch.status()
    watch.status()
    assert received[1] == {"site": "one"}


# ----------------------------------------------------------------- disabled

def test_disabled_is_a_no_op(tmp_path, observed, audit_rows):
    watch.register("fake", lambda settings: FakeWatcher("fake", settings))
    _configure(tmp_path, _WATCHING.format(extra="").replace("enable = true", "enable = false"))
    _enroll()
    audit_rows.clear()
    FakeWatcher.agents["fake"] = [_seen("bot-1")]
    summary = watch.sync(now=T0)
    assert summary == {"enabled": False, "ran": False, "platforms": {},
                       "reason": "Platform checks are turned off."}
    assert FakeWatcher.calls == [] and observed == [] and audit_rows == []
    path = watch.store_path()
    assert not path.exists() and not path.with_name(path.name + ".lock").exists()
    assert watch.status()["enabled"] is False and watch.unenrolled() == []


def test_checks_do_not_run_while_governance_is_off(fake, monkeypatch, observed):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    fake.agents["fake"] = [_seen("bot-1")]
    summary = watch.sync(now=T0)
    assert summary["ran"] is False and "governance" in summary["reason"]
    assert fake.calls == [] and not watch.store_path().exists()


def test_turning_checks_off_keeps_what_was_recorded(fake, monkeypatch):
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    monkeypatch.setenv("MAVERICK_AGENT_WATCH", "0")
    before = watch.store_path().read_bytes()
    assert watch.sync(now=T0 + 60)["ran"] is False
    assert watch.store_path().read_bytes() == before
    assert watch.status()["enabled"] is False and len(watch.unenrolled()) == 1


def test_only_one_check_runs_at_a_time(fake):
    started, release = threading.Event(), threading.Event()
    results: list[dict] = []

    def slow(self):
        started.set()
        release.wait(5)
        return []

    FakeWatcher.list_agents, original = slow, FakeWatcher.list_agents
    try:
        worker = threading.Thread(target=lambda: results.append(watch.sync(now=T0)))
        worker.start()
        assert started.wait(5)
        second = watch.sync(now=T0 + 1)
        release.set()
        worker.join(5)
    finally:
        FakeWatcher.list_agents = original
    assert second["ran"] is False and "already running" in second["reason"]
    assert results[0]["ran"] is True


# ---------------------------------------------------------- the saved record

def test_the_record_sits_beside_enrollment_and_is_private(fake):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1"), _seen("bot-2")]
    watch.sync(now=T0)
    path = watch.store_path()
    assert path.parent == xa.registry_path().parent and path.name == "external_agents_watch.json"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    stored = _stored()
    assert set(stored) == {"version", "platforms", "unenrolled", "agents"}
    assert set(stored["platforms"]["fake"]) == {
        "last_attempt_at", "last_success_at", "last_error", "last_error_at", "failures_in_a_row",
        "listed", "matched", "not_enrolled", "missing"}
    assert set(stored["unenrolled"]["fake"]["bot-2"]) == {
        "name", "state", "version", "updated_at", "first_seen_at", "last_seen_at"}
    assert set(stored["agents"][AGENT]) == {
        "external_ref", "listed", "name", "state", "version", "updated_at", "last_seen_at",
        "last_checked_at", "missing_runs", "missing_on_platform", "missing_since"}


def test_a_run_that_changes_nothing_but_the_time_still_records_the_attempt(fake):
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    watch.sync(now=T0 + 60)
    assert _platform()["last_success_at"] == T0 + 60


_BROKEN_STORES = [
    "{ not json",
    "[]",
    '{"version": 1}',
    '{"version": 99, "platforms": {}, "unenrolled": {}, "agents": {}}',
    '{"version": 1, "platforms": [], "unenrolled": {}, "agents": {}}',
    '{"version": 1, "platforms": {"fake": 7}, "unenrolled": {}, "agents": {}}',
    '{"version": 1, "platforms": {}, "unenrolled": {"fake": []}, "agents": {}}',
    '{"version": 1, "platforms": {}, "unenrolled": {"fake": {"bot-1": "x"}}, "agents": {}}',
    '{"version": 1, "platforms": {}, "unenrolled": {}, "agents": {"sf-quotebot": 3}}',
]


@pytest.mark.parametrize("payload", _BROKEN_STORES)
def test_a_record_that_cannot_be_read_is_never_overwritten_or_read_as_empty(fake, observed, payload):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]
    path = watch.store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    for refused in (lambda: watch.sync(now=T0), watch.status, watch.unenrolled,
                    lambda: watch.platform_view(AGENT)):
        with pytest.raises(watch.AgentWatchStoreError, match="cannot be read"):
            refused()
    assert path.read_text(encoding="utf-8") == payload
    # Fail closed: the platform was not even asked, and drift was told nothing.
    assert fake.calls == [] and observed == []


def test_junk_inside_a_readable_record_reads_as_nothing_not_as_an_error(fake):
    _enroll()
    watch.store_path().parent.mkdir(parents=True, exist_ok=True)
    watch.store_path().write_text(json.dumps({"version": 1, "platforms": {"fake": {
        "last_attempt_at": "noon", "listed": -3, "last_error": 7, "failures_in_a_row": "many"}},
        "unenrolled": {"fake": {"bot-2": {"first_seen_at": "x", "name": ["n"]}}},
        "agents": {AGENT: {"external_ref": "fake:bot-1", "missing_runs": "x",
                           "missing_on_platform": "yes"}}}), encoding="utf-8")
    row = _platform()
    assert (row["last_attempt_at"], row["listed"], row["last_error"], row["failures_in_a_row"]) \
        == (None, 0, "", 0)
    assert watch.unenrolled()[0]["name"] == "" and watch.unenrolled()[0]["first_seen_at"] is None
    assert watch.platform_view(AGENT)["missing_runs"] == 0
    fake.agents["fake"] = [_seen("bot-1"), _seen("bot-2")]
    assert watch.sync(now=T0)["platforms"]["fake"]["ok"] is True
    assert watch.unenrolled()[0]["first_seen_at"] == T0


def test_enrollment_that_cannot_be_read_stops_the_check_before_any_platform_is_asked(fake, observed):
    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]
    xa.registry_path().write_text("{ not json", encoding="utf-8")
    with pytest.raises(watch.AgentWatchStoreError, match="enrollment"):
        watch.sync(now=T0)
    with pytest.raises(watch.AgentWatchStoreError, match="enrollment"):
        watch.platform_view(AGENT)
    assert fake.calls == [] and observed == [] and not watch.store_path().exists()


def test_platforms_no_longer_configured_are_forgotten_at_the_next_check(tmp_path):
    _two_platforms(tmp_path)
    _enroll("on-other", ref="other:bot-9")
    FakeWatcher.agents = {"fake": [_seen("bot-1")],
                          "other": [_seen("bot-7", platform="other"), _seen("bot-9", platform="other")]}
    watch.sync(now=T0)
    assert watch.platform_view("on-other")["listed"] is True
    _configure(tmp_path, _WATCHING.format(extra=""))
    assert [row["platform"] for row in watch.unenrolled()] == ["fake"]  # hidden at once
    assert watch.platform_view("on-other")["watched"] is False
    watch.sync(now=T0 + 60)
    stored = _stored()
    assert set(stored["platforms"]) == {"fake"} and set(stored["unenrolled"]) == {"fake"}
    assert stored["agents"] == {}
    view = watch.platform_view("on-other")
    assert (view["watched"], view["checked"], view["listed"]) == (False, False, None)


def test_an_unreadable_platform_list_forgets_nothing(tmp_path):
    _two_platforms(tmp_path)
    _enroll("on-other", ref="other:bot-7")
    FakeWatcher.agents = {"fake": [_seen("bot-1")], "other": [_seen("bot-7", platform="other")]}
    watch.sync(now=T0)
    _configure(tmp_path, '[agent_watch]\nenable = true\nplatforms = "fake"\n')
    assert watch.settings()["platforms_readable"] is False
    summary = watch.sync(now=T0 + 60)
    assert summary["ran"] is True and summary["platforms"] == {}
    stored = _stored()
    assert set(stored["platforms"]) == {"fake", "other"} and set(stored["agents"]) == {"on-other"}


# -------------------------------------------------------------------- audit

def test_each_check_is_audited_with_counts_only(fake, audit_rows, tmp_path):
    _two_platforms(tmp_path)
    _enroll()
    FakeWatcher.agents["fake"] = [_seen("bot-1"), _seen("bot-2", name="Payroll helper")]
    FakeWatcher.failure["other"] = watch.WatchError("The platform did not answer in time.")
    watch.sync(now=T0)
    row, = [row for row in audit_rows if row["kind"] == "agent_watch_synced"]
    assert row == {"kind": "agent_watch_synced", "agent": "agent_watch", "platforms": 2,
                   "succeeded": 1, "failed": 1, "listed": 2, "matched": 1, "not_enrolled": 1,
                   "missing": 0}


def test_the_audit_row_reaches_the_real_audit_log(fake):
    from maverick.paths import data_dir
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    rows = [json.loads(line) for path in data_dir("audit").glob("*.ndjson")
            for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    synced, = [row for row in rows if row["kind"] == "agent_watch_synced"]
    assert synced["listed"] == 1 and synced["not_enrolled"] == 1


def test_an_audit_refusal_stops_the_check_from_being_recorded(fake, observed, monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit.errors import AuditRefused
    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]

    def refuse(*_a, **_kw):
        raise AuditRefused("signing key unavailable")

    monkeypatch.setattr(audit_pkg, "record", refuse)
    with pytest.raises(AuditRefused):
        watch.sync(now=T0)
    assert not watch.store_path().exists() and observed == []


# ------------------------------------------------------------------- status

def test_status_before_any_check(fake):
    status = watch.status()
    assert status["enabled"] is True and status["problems"] == []
    assert (status["sync_minutes"], status["missing_after_runs"]) == (60, 3)
    assert status["platforms"] == [{
        "name": "fake", "ready": True, "problem": "", "last_attempt_at": None,
        "last_success_at": None, "last_error": "", "last_error_at": None, "failures_in_a_row": 0,
        "listed": 0, "matched": 0, "not_enrolled": 0, "not_enrolled_shown": 0, "missing": 0}]
    assert (status["not_enrolled_count"], status["missing_count"]) == (0, 0)
    assert not watch.store_path().exists()  # reading writes nothing


# ------------------------------------------------------------------ Postgres

def test_with_postgres_the_platform_record_is_kept_there(fake, observed, records_in_postgres):
    from tests.new.conftest import saved_records

    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]
    watch.sync(now=T0)
    assert _platform()["last_success_at"] == T0
    assert not watch.store_path().exists()
    assert "external_agents_watch.json" in saved_records(records_in_postgres)


def test_with_postgres_a_damaged_platform_record_is_refused_and_left_alone(fake, observed, records_in_postgres):
    from maverick import record_documents
    from tests.new.conftest import saved_records

    _enroll()
    fake.agents["fake"] = [_seen("bot-1")]
    record_documents.at(watch.store_path()).write_text("{ not json")
    for refused in (lambda: watch.sync(now=T0), watch.status):
        with pytest.raises(watch.AgentWatchStoreError, match="cannot be read"):
            refused()
    assert fake.calls == []
    assert saved_records(records_in_postgres)["external_agents_watch.json"] == "{ not json"
