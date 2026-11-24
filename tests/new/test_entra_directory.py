"""Microsoft Entra directory lookups, proven without a tenant.

Microsoft Graph and the sign-in service are replaced by ``entra_kit.Graph``,
which answers in the documented shapes through ``httpx.MockTransport``; the
request code, paging, throttling, caching and settings are the real ones.
"""
from __future__ import annotations

import logging

import httpx
import pytest

from tests.new import entra_kit as kit
from tests.new.entra_kit import PEOPLE, Graph

ALICE, BOB, CAROL, DAVE = (PEOPLE[n] for n in ("alice", "bob", "carol", "dave"))


@pytest.fixture
def env(tmp_path, monkeypatch):
    from maverick import agent_watch, config, entra_directory

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("GRAPH_TENANT", kit.TENANT)
    monkeypatch.setenv("GRAPH_CLIENT", kit.CLIENT)
    monkeypatch.setenv("GRAPH_SECRET", kit.SECRET)
    monkeypatch.delenv("MAVERICK_ENTRA_DIRECTORY", raising=False)
    kit.write_config(tmp_path)
    entra_directory.reset_cache()
    agent_watch._TOKENS.clear()
    clock = kit.Clock()
    monkeypatch.setattr(entra_directory, "_monotonic", clock.monotonic)
    monkeypatch.setattr(entra_directory, "_sleep", clock.sleep)
    yield type("Env", (), {"path": tmp_path, "clock": clock})
    entra_directory.reset_cache()
    agent_watch._TOKENS.clear()
    config.reset_config_cache()


@pytest.fixture
def graph(env, monkeypatch) -> Graph:
    return kit.serve(monkeypatch, Graph())


def _directory():
    from maverick import entra_directory

    return entra_directory


# ------------------------------------------------------------------ roles


def test_a_direct_assignment_gives_the_role(graph):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Approver")]
    d = _directory()
    assert d.app_roles_for_object_id(ALICE) == {"SecondShift.Approver"}
    assert d.role_for_object_id(ALICE) == "approver"
    assert d.role_for_object_id(BOB) is None


def test_a_role_assigned_through_a_group_reaches_its_members_and_only_its_users(graph):
    graph.assignments = [kit.assignment(kit.GROUP, "SecondShift.Approver", "Group")]
    graph.groups = {kit.GROUP: [kit.member(BOB), kit.member(CAROL), kit.member(kit.GROUP2, "group"),
                                kit.member(kit.SP, "servicePrincipal")]}
    d = _directory()
    assert d.role_for_object_id(BOB) == "approver" and d.role_for_object_id(CAROL) == "approver"
    # A nested group does not carry the role, and neither does a service principal.
    assert d.role_for_object_id(kit.GROUP2) is None and d.role_for_object_id(kit.SP) is None
    assert d.role_for_object_id(DAVE) is None


def test_several_roles_the_strongest_wins_whatever_the_order(graph):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Viewer"),
                         kit.assignment(kit.GROUP, "SecondShift.Admin", "Group"),
                         kit.assignment(ALICE, "SecondShift.Approver")]
    graph.groups = {kit.GROUP: [kit.member(ALICE)]}
    d = _directory()
    assert d.app_roles_for_object_id(ALICE) == {"SecondShift.Viewer", "SecondShift.Approver", "SecondShift.Admin"}
    assert d.role_for_object_id(ALICE) == "admin"


def test_roles_nobody_maps_disabled_roles_and_the_default_access_role_give_nothing(graph):
    graph.roles = kit.app_roles(disabled=("SecondShift.Approver",))
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Unmapped"), kit.assignment(BOB, "SecondShift.Approver"),
                         kit.assignment(CAROL, kit.DEFAULT_ACCESS)]
    d = _directory()
    assert d.role_for_object_id(ALICE) is None  # held, but no [auth.oidc.role_map] entry
    assert d.app_roles_for_object_id(ALICE) == {"SecondShift.Unmapped"}
    assert d.role_for_object_id(BOB) is None and d.role_for_object_id(CAROL) is None


def test_everyone_who_holds_each_role_is_listed_with_groups_expanded(graph):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin"),
                         kit.assignment(kit.GROUP, "SecondShift.Approver", "Group"),
                         kit.assignment(BOB, "SecondShift.Approver")]
    graph.groups = {kit.GROUP: [kit.member(CAROL), kit.member(BOB)]}
    holders = _directory().role_holders()
    assert holders["SecondShift.Admin"] == {ALICE}
    assert holders["SecondShift.Approver"] == {BOB, CAROL}
    assert holders["SecondShift.Viewer"] == frozenset()


def test_the_exact_graph_requests_are_the_documented_ones(graph):
    graph.assignments = [kit.assignment(kit.GROUP, "SecondShift.Approver", "Group")]
    graph.groups = {kit.GROUP: [kit.member(BOB)]}
    _directory().role_holders()
    token, *reads = graph.requests
    assert token.url.host == "login.microsoftonline.com" and token.url.path == f"/{kit.TENANT}/oauth2/v2.0/token"
    assert all(r.method == "GET" and r.url.host == "graph.microsoft.com" and r.url.scheme == "https" for r in reads)
    assert graph.paths() == [f"/v1.0/servicePrincipals/{kit.SP}", f"/v1.0/servicePrincipals/{kit.SP}/appRoleAssignedTo",
                             f"/v1.0/groups/{kit.GROUP}/members"]
    assert reads[0].url.params["$select"] == "id,appRoles"
    assert reads[1].url.params["$top"] == "999"


def test_the_application_can_be_named_by_its_app_id_or_the_sign_in_client_id(env, graph):
    kit.write_config(env.path, body=kit.CONFIG.replace(f'service_principal_id = "{kit.SP}"', f'app_id = "{kit.APP}"'))
    _directory().reset_cache()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    assert _directory().role_for_object_id(ALICE) == "admin"
    assert graph.paths()[0] == f"/v1.0/servicePrincipals(appId='{kit.APP}')"
    _directory().reset_cache()
    kit.write_config(env.path, body=kit.CONFIG.replace(f'service_principal_id = "{kit.SP}"', ""))
    problems = _directory().settings()["problems"]
    assert problems and "service_principal_id or app_id" in problems[0]


# ----------------------------------------------------------------- limits


def test_a_long_list_is_read_across_pages(graph):
    graph.page_size = 2
    people = [f"{n:08x}-2222-4222-8222-{n:012x}" for n in range(1, 8)]
    graph.assignments = [kit.assignment(p, "SecondShift.Approver") for p in people]
    holders = _directory().role_holders()
    assert holders["SecondShift.Approver"] == set(people)
    assert len([p for p in graph.paths() if p.endswith("appRoleAssignedTo")]) == 4


def test_a_page_link_that_leaves_the_address_or_repeats_means_nobody(graph, monkeypatch):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    loop = httpx.Response(200, json={"value": [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals/"
                                     f"{kit.SP}/appRoleAssignedTo?$select=principalId,principalType,appRoleId&$top=999"})
    graph.script = [("appRoleAssignedTo", loop), ("appRoleAssignedTo", loop)]
    d = _directory()
    assert d.role_holders() == {} and d.role_for_object_id(ALICE) is None
    d.reset_cache()
    elsewhere = httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example/v1.0/servicePrincipals/"
                                          f"{kit.SP}/appRoleAssignedTo?$skiptoken=1"})
    graph.script = [("appRoleAssignedTo", elsewhere)]
    assert d.role_holders() == {}
    assert not [r for r in graph.requests if r.url.host == "evil.example"]


def test_a_list_longer_than_the_limits_is_refused_whole_not_cut_short(graph, monkeypatch):
    d = _directory()
    graph.assignments = [kit.assignment(p, "SecondShift.Approver")
                         for p in (f"{n:08x}-3333-4333-8333-{n:012x}" for n in range(1, 6))]
    monkeypatch.setattr(d, "_MAX_ASSIGNMENTS", 4)
    assert d.role_holders() == {}
    d.reset_cache()
    monkeypatch.setattr(d, "_MAX_ASSIGNMENTS", 100)
    monkeypatch.setattr(d, "_MAX_REQUESTS", 2)  # the application and one page, but no more
    graph.page_size = 2
    assert d.role_holders() == {}
    d.reset_cache()
    monkeypatch.setattr(d, "_MAX_REQUESTS", 80)
    monkeypatch.setattr(d, "_MAX_GROUPS", 1)
    graph.assignments = [kit.assignment(kit.GROUP, "SecondShift.Admin", "Group"),
                         kit.assignment(kit.GROUP2, "SecondShift.Admin", "Group")]
    assert d.role_holders() == {}


def test_a_group_with_more_members_than_the_limit_is_refused(graph, monkeypatch):
    d = _directory()
    graph.assignments = [kit.assignment(kit.GROUP, "SecondShift.Approver", "Group")]
    graph.groups = {kit.GROUP: [kit.member(p) for p in PEOPLE.values()]}
    monkeypatch.setattr(d, "_MAX_PEOPLE", 3)
    assert d.role_holders() == {}


# ------------------------------------------------------------- throttling


def _throttled(retry_after: str | None = "3") -> httpx.Response:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return httpx.Response(429, headers=headers, json={"error": {"code": "TooManyRequests"}})


def test_a_throttled_answer_is_retried_after_its_retry_after_and_then_succeeds(env, graph):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.script = [("appRoleAssignedTo", _throttled("3")), ("appRoleAssignedTo", _throttled("2"))]
    assert _directory().role_for_object_id(ALICE) == "admin"
    assert env.clock.slept == [3.0, 2.0]


def test_a_throttled_answer_without_a_usable_header_backs_off_a_little(env, graph):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.script = [("appRoleAssignedTo", _throttled(None)), ("appRoleAssignedTo", _throttled("Wed, 21 Oct 2026 07:28:00 GMT"))]
    assert _directory().role_for_object_id(ALICE) == "admin"
    assert env.clock.slept == [1.0, 2.0]


def test_throttling_that_does_not_end_or_asks_for_a_long_wait_means_no_role(env, graph):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.script = [("appRoleAssignedTo", _throttled("3"))] * 4
    d = _directory()
    assert d.role_for_object_id(ALICE) is None
    assert len(env.clock.slept) == 3  # three waits, then it gave up
    d.reset_cache()
    env.clock.slept.clear()
    graph.script = [("appRoleAssignedTo", _throttled("600"))]
    assert d.role_for_object_id(ALICE) is None and env.clock.slept == []  # never waits ten minutes


def test_the_whole_lookup_stops_at_its_time_limit(env, graph, monkeypatch):
    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    monkeypatch.setattr(d, "_RUN_SECONDS", 4.0)
    graph.script = [("appRoleAssignedTo", _throttled("3")), ("appRoleAssignedTo", _throttled("3"))]
    assert d.role_for_object_id(ALICE) is None  # the second wait would pass the limit


# --------------------------------------------------------------- failures


@pytest.mark.parametrize("answer", [
    httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied", "message": "secret-detail-xyz"}}),
    httpx.Response(401, json={}),
    httpx.Response(404, json={}),
    httpx.Response(500, text="boom"),
    httpx.Response(200, text="not json"),
    httpx.Response(200, json=["a list"]),
    httpx.Response(200, json={"value": "not a list"}),
    httpx.Response(200, json={"value": [{"principalId": "not-a-guid", "principalType": "User", "appRoleId": kit.ROLE_ID["SecondShift.Admin"]}]}),
    httpx.Response(200, json={"value": [{"principalId": ALICE, "principalType": "User"}]}),
    httpx.Response(302, headers={"Location": "https://evil.example/"}),
])
def test_a_failure_or_an_unreadable_answer_means_no_role_and_nobody(env, graph, caplog, answer):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.script = [("appRoleAssignedTo", answer)]
    d = _directory()
    with caplog.at_level(logging.DEBUG):
        assert d.role_for_object_id(ALICE) is None
        assert d.role_holders() == {} and d.principals_with_role() == set()
    assert "secret-detail-xyz" not in caplog.text
    assert not [r for r in graph.requests if r.url.host == "evil.example"]


def test_a_sign_in_that_is_refused_or_has_no_secret_means_no_role(env, graph, monkeypatch, caplog):
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.token_answer = httpx.Response(401, json={"error": "invalid_client", "error_description": "AADSTS7000215 bad"})
    d = _directory()
    with caplog.at_level(logging.DEBUG):
        assert d.role_for_object_id(ALICE) is None
    assert graph.graph_requests() == [] and "AADSTS7000215" not in caplog.text
    d.reset_cache()
    graph.token_answer = None
    monkeypatch.delenv("GRAPH_SECRET")
    before = len(graph.requests)
    assert d.role_for_object_id(ALICE) is None and len(graph.requests) == before  # not even a sign-in attempt


def test_a_network_error_or_a_blocked_address_means_no_role(graph, monkeypatch):
    from maverick.tools import _ssrf

    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]

    def refuse(url, timeout=None, **kw):
        raise _ssrf.BlockedHost("blocked")

    monkeypatch.setattr(_ssrf, "safe_client", refuse)
    assert d.role_for_object_id(ALICE) is None
    d.reset_cache()

    def down(url, timeout=None, **kw):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(_ssrf, "safe_client", down)
    assert d.role_for_object_id(ALICE) is None


def test_an_answer_over_the_size_bound_means_no_role(graph, monkeypatch):
    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    monkeypatch.setattr(d, "_MAX_BODY_BYTES", 200)
    assert d.role_for_object_id(ALICE) is None


def test_ids_that_are_not_object_ids_are_not_looked_up(graph):
    d = _directory()
    for bad in ("", None, "alice@example.com", "../etc", "1" * 40):
        assert d.app_roles_for_object_id(bad) == frozenset()
    assert graph.requests == []


# ------------------------------------------------------------------ cache


def test_answers_are_kept_for_the_cache_time_and_then_read_again(env, graph):
    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Approver")]
    assert d.role_for_object_id(ALICE) == "approver"
    first = len(graph.requests)
    graph.assignments = []  # the role is removed in Entra
    assert d.role_for_object_id(ALICE) == "approver" and d.role_for_object_id(BOB) is None
    assert len(graph.requests) == first  # one answer serves everyone for five minutes
    env.clock.advance(299)
    assert d.role_for_object_id(ALICE) == "approver"
    env.clock.advance(2)
    assert d.role_for_object_id(ALICE) is None and len(graph.requests) > first


def test_the_cache_time_is_a_setting_and_zero_keeps_nothing(env, graph):
    kit.write_config(env.path, extra="cache_minutes = 1")
    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    assert d.settings()["cache_minutes"] == 1 and d.role_for_object_id(ALICE) == "admin"
    graph.assignments = []
    env.clock.advance(61)
    assert d.role_for_object_id(ALICE) is None
    kit.write_config(env.path, extra="cache_minutes = 0")
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    assert d.role_for_object_id(ALICE) == "admin"
    graph.assignments = []
    assert d.role_for_object_id(ALICE) is None  # read again at once
    for bad in ("cache_minutes = 600", 'cache_minutes = "5"', "cache_minutes = -1", "cache_minutes = true"):
        kit.write_config(env.path, extra=bad)
        assert d.settings()["cache_minutes"] == 5


def test_a_failure_is_kept_briefly_so_a_broken_connection_is_not_hammered(env, graph):
    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.script = [("servicePrincipals", httpx.Response(500, text="down"))]
    assert d.role_for_object_id(ALICE) is None
    count = len(graph.requests)
    assert d.role_for_object_id(ALICE) is None and d.role_for_object_id(BOB) is None
    assert len(graph.requests) == count
    env.clock.advance(31)
    assert d.role_for_object_id(ALICE) == "admin"  # recovered once the pause ended


# ----------------------------------------------------- off / settings


def test_off_is_the_default_and_asks_nobody_anything(env, graph):
    kit.write_config(env.path, body="")
    d = _directory()
    assert d.enabled() is False and d.settings()["enable"] is False
    assert d.role_holders() == {} and d.role_for_object_id(ALICE) is None
    assert d.role_for_principal("user:alice") is None and d.principals_with_role() == set()
    with pytest.raises(d.DirectoryError):
        d.search_people("ali")
    assert graph.requests == []


def test_a_setting_that_is_not_usable_keeps_it_off_and_says_why_without_repeating_values(env, graph):
    typed_secret = "super-secret-typed-in-by-mistake"  # pragma: allowlist secret
    kit.write_config(env.path, body=kit.CONFIG.replace('client_secret_env = "GRAPH_SECRET"',
                                                       f'client_secret_env = "{typed_secret}!"'))
    cfg = _directory().settings()
    assert cfg["enable"] is False and cfg["wanted"] is True
    assert any("client_secret_env" in p for p in cfg["problems"]) and typed_secret not in str(cfg)
    assert _directory().role_for_object_id(ALICE) is None and graph.requests == []


def test_the_environment_can_switch_it_on_or_off(env, graph, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTRA_DIRECTORY", "0")
    assert _directory().enabled() is False
    monkeypatch.setenv("MAVERICK_ENTRA_DIRECTORY", "1")
    assert _directory().enabled() is True


# ---------------------------------------------------------------- picker


def test_search_returns_only_the_four_fields_sorted_and_asks_for_no_more(graph):
    graph.users = [kit.user_row("Zoe Park", "zoe@example.com", PEOPLE["erin"], "Analyst"),
                   kit.user_row("Alan Ames", None, PEOPLE["frank"], None, upn="alan@corp.example.com"),
                   {"id": "not-a-guid", "displayName": "Broken", "mail": "b@example.com"},
                   {"id": PEOPLE["dave"], "displayName": "No Address"}]
    found = _directory().search_people("  a'l  ")
    assert found == [
        {"display_name": "Alan Ames", "email": "alan@corp.example.com", "object_id": PEOPLE["frank"], "job_title": ""},
        {"display_name": "Zoe Park", "email": "zoe@example.com", "object_id": PEOPLE["erin"], "job_title": "Analyst"}]
    assert all(set(p) == {"display_name", "email", "object_id", "job_title"} for p in found)
    request, = [r for r in graph.graph_requests() if r.url.path == "/v1.0/users"]
    assert request.headers["consistencylevel"] == "eventual"
    assert request.url.params["$top"] == "10"
    assert set(request.url.params["$select"].split(",")) == {"id", "displayName", "mail", "userPrincipalName", "jobTitle"}
    assert "startswith(displayName,'a''l')" in request.url.params["$filter"]  # the quote cannot end the string
    assert "startswith(mail,'a''l')" in request.url.params["$filter"]


def test_search_keeps_at_most_ten_and_finds_nobody_for_a_short_or_empty_query(graph):
    graph.users = [kit.user_row(f"Person {n:02d}", f"p{n}@example.com", f"{n:08x}-4444-4444-8444-{n:012x}") for n in range(1, 16)]
    d = _directory()
    assert len(d.search_people("pe")) == 10
    graph.requests.clear()
    for short in ("", " ", "a", None):
        assert d.search_people(short) == []
    assert graph.requests == []


def test_search_that_cannot_be_completed_says_so_in_plain_words(env, graph):
    d = _directory()
    graph.script = [("/users", httpx.Response(403, json={"error": {"message": "Insufficient privileges"}}))]
    with pytest.raises(d.DirectoryError) as caught:
        d.search_people("alice")
    assert "email" in str(caught.value) and "Insufficient" not in str(caught.value)


# ------------------------------------------------------------ no secrets


def test_no_token_or_secret_reaches_a_log_an_error_or_the_cache_answers(env, graph, caplog):
    d = _directory()
    graph.assignments = [kit.assignment(ALICE, "SecondShift.Admin")]
    graph.users = [kit.user_row("Alan Ames", "alan@example.com", PEOPLE["frank"])]
    with caplog.at_level(logging.DEBUG):
        d.role_for_object_id(ALICE)
        d.search_people("alan")
        graph.script = [("servicePrincipals", httpx.Response(401, json={"error": {"message": kit.TOKEN}}))]
        d.reset_cache()
        d.role_for_object_id(ALICE)
        d.reset_cache()
        graph.token_answer = httpx.Response(400, json={"error": "invalid_client", "error_description": kit.SECRET})
        agent_watch = __import__("maverick.agent_watch", fromlist=["x"])
        agent_watch._TOKENS.clear()
        d.role_for_object_id(ALICE)
        with pytest.raises(d.DirectoryError) as caught:
            d.reset_cache()
            d.search_people("alan")
    for text in (caplog.text, str(caught.value), repr(d.role_holders()), repr(d.search_people)):
        assert kit.TOKEN not in text and kit.SECRET not in text
