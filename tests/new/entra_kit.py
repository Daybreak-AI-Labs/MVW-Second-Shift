"""A stand-in for Microsoft Graph and the Entra sign-in service, for the directory tests.

Answers are shaped like the documented ones (service principal with ``appRoles``,
``appRoleAssignedTo`` rows, group ``members`` as directory objects, ``users``
with ``mail``/``jobTitle``) and are served through ``httpx.MockTransport`` in
place of the guarded outbound client, so the real request code runs. Nothing
here reaches Microsoft.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from urllib.parse import parse_qs, unquote, urlsplit

import httpx

SP = "5a5a5a5a-0000-4000-8000-000000000001"
APP = "6b6b6b6b-0000-4000-8000-000000000002"
TENANT = "7c7c7c7c-0000-4000-8000-000000000003"
CLIENT = "8d8d8d8d-0000-4000-8000-000000000004"
SECRET = "graph-secret-value-7Q2"  # pragma: allowlist secret
TOKEN = "graph-access-token-ZX81"
ROLE_ID = {"SecondShift.Admin": "11111111-0000-4000-8000-0000000000a1",
           "SecondShift.Approver": "11111111-0000-4000-8000-0000000000a2",
           "SecondShift.Viewer": "11111111-0000-4000-8000-0000000000a3",
           "SecondShift.Unmapped": "11111111-0000-4000-8000-0000000000a4"}
DEFAULT_ACCESS = "00000000-0000-0000-0000-000000000000"
PEOPLE = {name: f"{n:08x}-1111-4111-8111-{n:012x}" for n, name in enumerate(
    ["alice", "bob", "carol", "dave", "erin", "frank"], start=1)}
GROUP = "99999999-0000-4000-8000-0000000000b1"
GROUP2 = "99999999-0000-4000-8000-0000000000b2"


def app_roles(disabled: tuple[str, ...] = ()) -> list[dict]:
    return [{"id": rid, "value": value, "displayName": value.split(".")[1], "description": value,
             "isEnabled": value not in disabled, "allowedMemberTypes": ["User"], "origin": "Application"}
            for value, rid in ROLE_ID.items()]


def assignment(principal: str, role: str, kind: str = "User") -> dict:
    return {"id": "x" + principal[:8], "appRoleId": ROLE_ID.get(role, role), "principalId": principal,
            "principalType": kind, "principalDisplayName": "Somebody", "resourceId": SP,
            "resourceDisplayName": "Second Shift", "createdDateTime": "2026-01-02T03:04:05Z"}


def member(oid: str, kind: str = "user") -> dict:
    return {"@odata.type": f"#microsoft.graph.{kind}", "id": oid}


def user_row(name: str, email: str | None, oid: str, title: str | None = None, upn: str | None = None) -> dict:
    return {"id": oid, "displayName": name, "mail": email, "userPrincipalName": upn or (email or "x@example.com"),
            "jobTitle": title, "officeLocation": "Building 4", "mobilePhone": "+1 555 0100"}


class Graph:
    """What the directory says now; change a field between calls to change what
    the next (uncached) lookup sees."""

    def __init__(self) -> None:
        self.roles = app_roles()
        self.assignments: list[dict] = []
        self.groups: dict[str, list[dict]] = {}
        self.users: list[dict] = []
        self.page_size = 999
        self.requests: list[httpx.Request] = []
        self.script: list[tuple[str, httpx.Response]] = []  # (path fragment, answer) consumed in order
        self.token_answer: httpx.Response | None = None

    def graph_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == "graph.microsoft.com"]

    def paths(self) -> list[str]:
        return [unquote(r.url.path) for r in self.graph_requests()]

    def _page(self, request: httpx.Request, rows: list[dict]) -> httpx.Response:
        query = parse_qs(urlsplit(str(request.url)).query)
        start = int(query.get("$skiptoken", ["0"])[0])
        batch = rows[start:start + self.page_size]
        body: dict = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#x", "value": batch}
        if start + self.page_size < len(rows):
            body["@odata.nextLink"] = f"https://graph.microsoft.com{request.url.path}?$top=999&$skiptoken={start + self.page_size}"
        return httpx.Response(200, json=body)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            return self.token_answer or httpx.Response(200, json={
                "token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": TOKEN})
        path = unquote(request.url.path)
        for index, (fragment, answer) in enumerate(self.script):
            if fragment in path:
                del self.script[index]
                return answer
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        if path in (f"/v1.0/servicePrincipals/{SP}", f"/v1.0/servicePrincipals(appId='{APP}')"):
            return httpx.Response(200, json={"@odata.context": "x", "id": SP, "appRoles": self.roles})
        if path == f"/v1.0/servicePrincipals/{SP}/appRoleAssignedTo":
            return self._page(request, self.assignments)
        if path.startswith("/v1.0/groups/") and path.endswith("/members"):
            group = path.split("/")[3]
            return self._page(request, self.groups[group]) if group in self.groups else httpx.Response(404, json={})
        if path == "/v1.0/users":
            return httpx.Response(200, json={"@odata.context": "x", "@odata.count": len(self.users), "value": self.users})
        return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})


def serve(monkeypatch, graph: Graph) -> Graph:
    """Answer every guarded outbound request from ``graph``."""
    from maverick.tools import _ssrf

    @contextmanager
    def client(url, timeout=None, **kw):
        with httpx.Client(transport=httpx.MockTransport(graph), timeout=timeout) as value:
            yield value

    monkeypatch.setattr(_ssrf, "safe_client", client)
    return graph


class Clock:
    """A clock the directory code reads in place of the real one."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


CONFIG = f'''
[entra_directory]
enable = true
tenant_id_env = "GRAPH_TENANT"
client_id_env = "GRAPH_CLIENT"
client_secret_env = "GRAPH_SECRET"
service_principal_id = "{SP}"
{{extra}}

[auth.oidc.role_map]
"SecondShift.Admin" = "admin"
"SecondShift.Approver" = "approver"
"SecondShift.Viewer" = "viewer"
'''


def write_config(tmp_path, extra: str = "", body: str | None = None) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text((body if body is not None else CONFIG).replace("{extra}", extra),
                                          encoding="utf-8")
    config.reset_config_cache()


def json_of(response: httpx.Response) -> dict:
    return json.loads(response.content)
