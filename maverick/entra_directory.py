"""Read-only lookups in the Microsoft Entra directory, with this app's own credentials.

Three features have no browser session to carry a person's Entra app roles:
Teams approval cards (who receives one, whether the person who pressed a
button may decide), the rule that asks whether another approver is available,
and the owner picker on the add-agent form. This module answers three
questions for them, through Microsoft Graph v1.0 and nothing else::

    app roles a person holds now (by Entra object id)        role_for_object_id
    everyone who holds each Second Shift app role            role_holders
    people matching a name or email, for the picker          search_people

Settings (``[entra_directory]``; off until an administrator turns it on)::

    enable = false
    tenant_id_env = "SECOND_SHIFT_GRAPH_TENANT_ID"      # NAMES of environment variables,
    client_id_env = "SECOND_SHIFT_GRAPH_CLIENT_ID"      # never the values
    client_secret_env = "SECOND_SHIFT_GRAPH_CLIENT_SECRET"
    service_principal_id = ""   # object id of Second Shift's enterprise application, or
    app_id = ""                 # its application (client) id; with neither, [auth.oidc] client_id
    cache_minutes = 5           # 0 to 60; answers are kept in memory only

The Graph requests, with the least privileged application permission each
needs (Microsoft Learn, checked when this was written; nothing here has been
run against a real tenant):

* ``GET /servicePrincipals/{id}?$select=id,appRoles`` or
  ``GET /servicePrincipals(appId='{appId}')?$select=id,appRoles`` -- the app
  role ids and their values. Application.Read.All.
  https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0
* ``GET /servicePrincipals/{id}/appRoleAssignedTo?$select=...&$top=999`` -- the
  users and groups assigned an app role. Application.Read.All.
  https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0
* ``GET /groups/{id}/members?$select=id&$top=999`` -- the direct members of a
  group that was assigned a role. GroupMember.ReadBasic.All. Direct members
  only: Microsoft documents that an assignment to a group does not cascade to
  nested groups, so this does not expand them either.
  https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal
* ``GET /users?$filter=startswith(...)&$select=...&$top=10`` -- the picker.
  User.Read.All (needed only for the picker; the role lookups do not use it).
  https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0

Paging follows ``@odata.nextLink`` (at most 999 rows a page). Throttling: a 429
or 503 is retried after its ``Retry-After`` seconds, a few times at most and
only inside the run's time limit.
https://learn.microsoft.com/en-us/graph/throttling

What it does not do: write anything, take an address from a caller (every
address is built here from the fixed Graph host and ids checked to be GUIDs; a
paging link must stay on the address being read), log or return a token or the
secret, or guess. A failure, a refusal, an answer in an unexpected shape or a
list longer than the limits means "no role" and "nobody", and is kept as such
for half a minute so a broken connection is not retried on every click.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlencode

log = logging.getLogger(__name__)

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_SCOPE = "https://graph.microsoft.com/.default"

#: Bounds that are not settings.
_REQUEST_SECONDS = 15.0
_RUN_SECONDS = 60.0          # one lookup, all its requests and waits
_MAX_REQUESTS = 80           # one lookup
_MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_RETRIES = 3
_MAX_WAIT_SECONDS = 10.0
_PAGE_SIZE = 999
_MAX_ASSIGNMENTS = 10_000
_MAX_GROUPS = 50
_MAX_PEOPLE = 50_000
_MAX_ROLES = 100
_MAX_VALUE = 256
_FAILURE_SECONDS = 30.0
_MAX_CACHED = 500
_MAX_RESOLVED_PEOPLE = 1000
#: The picker.
SEARCH_LIMIT = 10
_MIN_QUERY = 2
_MAX_QUERY = 64

_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}")
_CREDENTIAL_KEYS = ("tenant_id_env", "client_id_env", "client_secret_env")


class DirectoryError(Exception):
    """A lookup could not be completed. The message is a plain sentence that
    holds nothing from Microsoft's answer and nothing secret."""


# ---------------------------------------------------------------- settings


def _section() -> dict:
    try:
        from .config import load_config

        section = (load_config() or {}).get("entra_directory")
    except Exception:  # noqa: BLE001 -- unreadable settings turn the directory off
        return {}
    return section if isinstance(section, dict) else {}


def settings() -> dict:
    """The validated ``[entra_directory]`` section.

    ``enable`` is true only when the switch is on and the three credential
    names, the Second Shift application and the cache time are all usable;
    ``problems`` says in plain words what is not. ``MAVERICK_ENTRA_DIRECTORY=0/1``
    overrides the switch. A value is never repeated in ``problems``."""
    from ._envparse import coerce_bool
    from .config import env_flag

    section = _section()
    problems: list[str] = []
    wanted = coerce_bool(section.get("enable"), False)
    override = env_flag("MAVERICK_ENTRA_DIRECTORY")
    if override is not None:
        wanted = override
    out: dict[str, Any] = {"wanted": wanted}
    for key in _CREDENTIAL_KEYS:
        value = section.get(key)
        if isinstance(value, str) and _ENV_NAME.fullmatch(value):
            out[key] = value
        else:
            out[key] = ""
            if wanted:
                problems.append(f"[entra_directory] needs {key}: the name of an environment variable "
                                "(letters, digits and underscores), not the value itself.")
    out["service_principal_id"] = _guid_setting(section, "service_principal_id", problems, wanted)
    out["app_id"] = _guid_setting(section, "app_id", problems, wanted)
    if wanted and not (out["service_principal_id"] or out["app_id"] or _oidc_client_id()):
        problems.append("[entra_directory] needs service_principal_id or app_id: which Second Shift "
                        "application in Entra holds the app roles.")
    raw = section.get("cache_minutes", 5)
    minutes = raw if isinstance(raw, int) and not isinstance(raw, bool) and 0 <= raw <= 60 else 5
    out["cache_minutes"] = minutes
    out["enable"] = bool(wanted and not problems)
    out["problems"] = problems
    return out


def _guid_setting(section: dict, key: str, problems: list[str], wanted: bool) -> str:
    value = section.get(key)
    if value in (None, ""):
        return ""
    if isinstance(value, str) and _GUID.fullmatch(value.strip()):
        return value.strip().lower()
    if wanted:
        problems.append(f"[entra_directory] {key} must be an id like 11111111-2222-3333-4444-555555555555.")
    return ""


def _oidc_client_id() -> str:
    try:
        from .oidc import load_oidc_config

        value = str(load_oidc_config().client_id or "").strip().lower()
    except Exception:  # noqa: BLE001
        return ""
    return value if _GUID.fullmatch(value) else ""


def enabled() -> bool:
    """Whether directory lookups are on and set up. Off is the default, and
    off changes nothing anywhere else."""
    return bool(settings()["enable"])


def _application(cfg: dict) -> str:
    """The address part naming Second Shift's service principal."""
    if cfg["service_principal_id"]:
        return f"/{cfg['service_principal_id']}"
    app = cfg["app_id"] or _oidc_client_id()
    return f"(appId='{app}')"


# ------------------------------------------------------------------- clock

def _monotonic() -> float:
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


# ------------------------------------------------------------------- cache

_LOCK = threading.Lock()
_CACHE: dict[tuple, tuple[float, Any]] = {}
_FAILED = object()


def reset_cache() -> None:
    """Forget every kept answer."""
    with _LOCK:
        _CACHE.clear()


def _cached(key: tuple, cfg: dict, load: Callable[[], Any]) -> Any:
    """``load()`` kept for ``cache_minutes``; ``None`` when it failed (a
    failure is kept for half a minute, never longer than the cache time)."""
    ttl = cfg["cache_minutes"] * 60.0
    key = (cfg["tenant_id_env"], cfg["client_id_env"], cfg["client_secret_env"], _application(cfg), *key)
    if ttl > 0:
        with _LOCK:
            kept = _CACHE.get(key)
            if kept is not None and kept[0] > _monotonic():
                return None if kept[1] is _FAILED else kept[1]
    try:
        value = load()
        stored, lifetime = value, ttl
    except DirectoryError as exc:
        log.warning("entra directory: a lookup failed (%s)", exc)
        value, stored, lifetime = None, _FAILED, min(ttl, _FAILURE_SECONDS)
    except Exception as exc:  # noqa: BLE001 -- nothing else may escape into an approval
        log.warning("entra directory: a lookup failed unexpectedly (%s)", type(exc).__name__)
        value, stored, lifetime = None, _FAILED, min(ttl, _FAILURE_SECONDS)
    if lifetime > 0:
        with _LOCK:
            if len(_CACHE) >= _MAX_CACHED:
                now = _monotonic()
                for stale in [k for k, (until, _v) in _CACHE.items() if until <= now]:
                    del _CACHE[stale]
                while len(_CACHE) >= _MAX_CACHED:
                    del _CACHE[min(_CACHE, key=lambda k: _CACHE[k][0])]
            _CACHE[key] = (_monotonic() + lifetime, stored)
    return value


# ------------------------------------------------------------ guarded reads


class _Run:
    """The reads of one lookup: one token, one request budget, one time limit."""

    def __init__(self, cfg: dict) -> None:
        self._stop_at = _monotonic() + _RUN_SECONDS
        self._requests = 0
        self._token = self._sign_in(cfg)

    @staticmethod
    def _sign_in(cfg: dict) -> str:
        from . import agent_watch
        from .agent_watch import WatchError

        try:
            tenant, client, secret = (
                agent_watch.secret_named(cfg[key], f"{key} in [entra_directory]") for key in _CREDENTIAL_KEYS)
            if not _TENANT.fullmatch(tenant) or not _CLIENT_ID.fullmatch(client):
                raise DirectoryError("The tenant id or client id the settings point to is not a valid id.")
            return agent_watch.client_credentials_token(
                _TOKEN_URL.format(tenant=tenant), client_id=client, client_secret=secret, scope=_SCOPE,
                timeout=_REQUEST_SECONDS)
        except WatchError as exc:  # its sentences never carry the secret or Microsoft's own text
            raise DirectoryError(str(exc)) from None

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> dict:
        """One GET answered with a JSON object, retrying a throttled answer
        after ``Retry-After`` inside the run's limits."""
        waited = 0
        while True:
            self._requests += 1
            if self._requests > _MAX_REQUESTS:
                raise DirectoryError("The directory needed more requests than this check allows.")
            left = self._stop_at - _monotonic()
            if left <= 0:
                raise DirectoryError("Microsoft Graph did not answer in time.")
            status, retry_after, body = _send(url, self._token, headers or {}, min(_REQUEST_SECONDS, left))
            if status == 200:
                return _json_object(body)
            if status in (429, 503) and waited < _MAX_RETRIES:
                wait = _retry_seconds(retry_after, waited)
                if wait > _MAX_WAIT_SECONDS or wait >= self._stop_at - _monotonic():
                    raise DirectoryError("Microsoft Graph is limiting requests at the moment.")
                _sleep(wait)
                waited += 1
                continue
            if status == 401:
                from . import agent_watch

                agent_watch._forget_token(self._token)
            raise DirectoryError(_status_sentence(status))

    def rows(self, url: str) -> Iterator[dict]:
        """Every row of a paged list, following ``@odata.nextLink`` only while
        it stays on the address being read."""
        from . import agent_watch
        from .agent_watch import WatchError

        seen: set[str] = set()
        current: str | None = url
        while current is not None:
            if current in seen:
                raise DirectoryError("Microsoft Graph's list pointed back to a page already read.")
            seen.add(current)
            page = self.get(current)
            batch = page.get("value")
            if not isinstance(batch, list) or not all(isinstance(row, dict) for row in batch):
                raise DirectoryError("Microsoft Graph's answer was not in the expected form.")
            yield from batch
            try:
                current = agent_watch.odata_next(page, current)
            except WatchError:
                raise DirectoryError("Microsoft Graph's answer was not in the expected form.") from None


def _retry_seconds(header: str | None, attempt: int) -> float:
    try:
        seconds = float(str(header).strip())
        if 0 <= seconds < 3600:
            return seconds
    except (TypeError, ValueError):
        pass
    return float(2 ** attempt)  # no usable header (a date, or none): back off


def _status_sentence(status: int) -> str:
    if status in (401, 403):
        return ("Microsoft Graph refused the lookup. Check the client id and secret, and that an "
                "administrator granted the permissions named in the Entra directory guide.")
    if status == 404:
        return "Microsoft Graph has no such application. Check service_principal_id or app_id."
    if status in (429, 503):
        return "Microsoft Graph is limiting requests at the moment."
    return f"Microsoft Graph answered with HTTP {status}, which this check does not expect."


def _send(url: str, token: str, headers: dict[str, str], timeout: float) -> tuple[int, str | None, bytes]:
    """One request through the outbound guard: status, ``Retry-After`` and the
    body of a 200 (bounded; anything larger is an error)."""
    import httpx

    from .enterprise import EgressBlocked
    from .tools import _ssrf

    if not url.startswith(GRAPH_ROOT + "/"):
        raise DirectoryError("The directory only reads from Microsoft Graph.")
    sent = {"Accept": "application/json", **headers, "Authorization": f"Bearer {token}"}
    try:
        with _ssrf.safe_client(url, timeout=timeout) as client:
            with client.stream("GET", url, headers=sent) as response:
                status = response.status_code
                retry = response.headers.get("Retry-After")
                if status != 200:
                    return status, retry, b""
                return status, retry, _read(response, _monotonic() + timeout)
    except DirectoryError:
        raise
    except _ssrf.BlockedHost:
        raise DirectoryError("This installation does not allow connections to Microsoft Graph.") from None
    except EgressBlocked:
        raise DirectoryError("This installation's network rules do not allow connections to "
                             "Microsoft Graph.") from None
    except httpx.TimeoutException:
        raise DirectoryError("Microsoft Graph did not answer in time.") from None
    except (httpx.HTTPError, httpx.InvalidURL, OSError):
        raise DirectoryError("Microsoft Graph could not be reached.") from None


def _read(response: Any, stop_at: float) -> bytes:
    body = bytearray()
    for chunk in response.iter_bytes(chunk_size=65536):
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise DirectoryError("Microsoft Graph's answer was larger than this check accepts.")
        body.extend(chunk)
        if _monotonic() > stop_at:
            raise DirectoryError("Microsoft Graph did not answer in time.")
    return bytes(body)


def _json_object(body: bytes) -> dict:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        raise DirectoryError("Microsoft Graph's answer was not in the expected form.") from None
    if not isinstance(parsed, dict):
        raise DirectoryError("Microsoft Graph's answer was not in the expected form.")
    return parsed


def _guid(value: Any) -> str:
    if not isinstance(value, str) or not _GUID.fullmatch(value):
        raise DirectoryError("Microsoft Graph's answer was not in the expected form.")
    return value.lower()


# ------------------------------------------------------------- role holders


def _build_holders(cfg: dict) -> dict[str, frozenset[str]]:
    """App role value -> object ids of the people who hold it, directly or
    through a group assigned the role. Raises :class:`DirectoryError` unless
    every list was read to its end inside the limits."""
    run = _Run(cfg)
    sp = run.get(f"{GRAPH_ROOT}/servicePrincipals{_application(cfg)}?$select=id,appRoles")
    sp_id = _guid(sp.get("id"))
    defined = sp.get("appRoles")
    if not isinstance(defined, list) or len(defined) > _MAX_ROLES:
        raise DirectoryError("Microsoft Graph's answer was not in the expected form.")
    values: dict[str, str] = {}
    for role in defined:
        if not isinstance(role, dict):
            raise DirectoryError("Microsoft Graph's answer was not in the expected form.")
        value = role.get("value")
        if role.get("isEnabled", True) is not True or not isinstance(value, str) or not value:
            continue  # a disabled role is not issued; the default role has no value
        if len(value) <= _MAX_VALUE:
            values[_guid(role.get("id"))] = value

    people: dict[str, set[str]] = {value: set() for value in values.values()}
    groups: dict[str, set[str]] = {}
    query = urlencode({"$select": "principalId,principalType,appRoleId", "$top": _PAGE_SIZE}, safe="$,")
    count = 0
    for row in run.rows(f"{GRAPH_ROOT}/servicePrincipals/{sp_id}/appRoleAssignedTo?{query}"):
        count += 1
        if count > _MAX_ASSIGNMENTS:
            raise DirectoryError("More people are assigned Second Shift roles than this check reads.")
        value = values.get(_guid(row.get("appRoleId")))
        kind = row.get("principalType")
        if value is None or kind not in ("User", "Group"):
            continue
        who = _guid(row.get("principalId"))
        if kind == "User":
            people[value].add(who)
        else:
            groups.setdefault(who, set()).add(value)
    if len(groups) > _MAX_GROUPS:
        raise DirectoryError("More groups are assigned Second Shift roles than this check reads.")
    total = sum(len(found) for found in people.values())
    members = urlencode({"$select": "id", "$top": _PAGE_SIZE}, safe="$,")
    for group, group_values in groups.items():
        for row in run.rows(f"{GRAPH_ROOT}/groups/{group}/members?{members}"):
            if row.get("@odata.type") != "#microsoft.graph.user":
                continue  # a device, a service principal; nested groups do not carry the role
            who = _guid(row.get("id"))
            total += len(group_values)
            if total > _MAX_PEOPLE:
                raise DirectoryError("More people hold Second Shift roles than this check reads.")
            for value in group_values:
                people[value].add(who)
    return {value: frozenset(found) for value, found in people.items()}


def role_holders() -> dict[str, frozenset[str]]:
    """Every Second Shift app role value -> the object ids (lower case) that
    hold it now, groups expanded. Empty when the directory is off or the answer
    could not be read: nobody."""
    cfg = settings()
    if not cfg["enable"]:
        return {}
    return _cached(("holders",), cfg, lambda: _build_holders(cfg)) or {}


def app_roles_for_object_id(object_id: object) -> frozenset[str]:
    """The Second Shift app role values this person holds now."""
    who = str(object_id or "").strip().lower()
    if not _GUID.fullmatch(who):
        return frozenset()
    return frozenset(value for value, found in role_holders().items() if who in found)


# --------------------------------------------------------- roles for people


def _mapped(values: frozenset[str]) -> str | None:
    """The one role these app role values map to under
    ``[auth.oidc.role_map]``, by the sign-in rule (the strongest wins)."""
    from maverick_dashboard import sign_in_roles

    role_map = sign_in_roles.load_settings().role_map
    return sign_in_roles.strongest(role_map[value] for value in values if value in role_map)


def role_for_object_id(object_id: object) -> str | None:
    """The role this person's current Entra app roles map to, or ``None``."""
    try:
        values = app_roles_for_object_id(object_id)
        return _mapped(values) if values else None
    except Exception as exc:  # noqa: BLE001 -- a role that cannot be worked out is no role
        log.warning("entra directory: a role could not be worked out (%s)", type(exc).__name__)
        return None


def object_ids_for(principal: object) -> set[str]:
    """The Entra object ids Second Shift knows for a user: Teams accounts an
    administrator linked to them and those it recognises from their sign-in."""
    from . import teams_identity

    who = teams_identity.normalize_principal(principal)
    return {str(person["teams_id"]).lower() for person in teams_identity.reachable_people()
            if person["principal"] == who}


def role_for_principal(principal: object) -> str | None:
    """The role a person without a session gets from Entra: what their current
    app roles map to. ``None`` when the directory is off, the person's object id
    is not known, or anything could not be read."""
    try:
        if not enabled():
            return None
        from maverick_dashboard import sign_in_roles

        found = {role for oid in object_ids_for(principal) if (role := role_for_object_id(oid))}
        return sign_in_roles.strongest(found)
    except Exception as exc:  # noqa: BLE001
        log.warning("entra directory: a role could not be worked out (%s)", type(exc).__name__)
        return None


def principals_with_role() -> set[str]:
    """Second Shift users whose role can come from Entra: holders of a mapped
    app role who are linked to a Teams account or have signed in. Bounded;
    empty when the directory is off or unreadable."""
    try:
        if not enabled():
            return set()
        from maverick_dashboard import sign_in_roles

        from . import teams_identity

        role_map = sign_in_roles.load_settings().role_map
        ids = sorted({oid for value, found in role_holders().items() if value in role_map for oid in found})
        if len(ids) > _MAX_RESOLVED_PEOPLE:
            raise DirectoryError("More people hold Second Shift roles than this check resolves.")
        wanted = set(ids)
        people = {person["principal"] for person in teams_identity.reachable_people()
                  if str(person["teams_id"]).lower() in wanted}
        for oid in ids:
            principal = teams_identity.directory_principal(oid)
            if principal:
                people.add(principal)
        return {person for person in people if person}
    except Exception as exc:  # noqa: BLE001
        log.warning("entra directory: the people holding roles could not be listed (%s)", type(exc).__name__)
        return set()


# ------------------------------------------------------------------ picker


def _clean_query(text: object) -> str:
    cleaned = "".join(ch for ch in str(text or "") if ch.isprintable()).strip()
    return cleaned[:_MAX_QUERY]


def _person(row: dict) -> dict | None:
    """The four fields the picker shows, or ``None`` for a row that is not a
    person we can name."""
    try:
        oid = _guid(row.get("id"))
    except DirectoryError:
        return None
    email = row.get("mail") if isinstance(row.get("mail"), str) and row.get("mail") else row.get("userPrincipalName")
    name = row.get("displayName")
    title = row.get("jobTitle")
    if not isinstance(email, str) or not email or not isinstance(name, str):
        return None
    return {"display_name": name[:200], "email": email[:254], "object_id": oid,
            "job_title": title[:200] if isinstance(title, str) else ""}


def _build_search(cfg: dict, text: str) -> list[dict]:
    quoted = text.replace("'", "''")
    fields = ("displayName", "mail", "userPrincipalName")
    query = urlencode({
        "$filter": " or ".join(f"startswith({field},'{quoted}')" for field in fields),
        "$select": "id,displayName,mail,userPrincipalName,jobTitle",
        "$top": SEARCH_LIMIT,
        "$count": "true",
    }, safe="$(),'")
    page = _Run(cfg).get(f"{GRAPH_ROOT}/users?{query}", headers={"ConsistencyLevel": "eventual"})
    rows = page.get("value")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise DirectoryError("Microsoft Graph's answer was not in the expected form.")
    found = [person for row in rows[:SEARCH_LIMIT] if (person := _person(row)) is not None]
    found.sort(key=lambda item: (item["display_name"].casefold(), item["email"].casefold()))
    return found


def search_people(query: object) -> list[dict]:
    """People whose name, email or sign-in name starts with ``query``: at most
    ten, each with ``display_name``, ``email``, ``object_id`` and ``job_title``
    and nothing else. A query under two characters finds nobody. Raises
    :class:`DirectoryError` (a plain sentence) when the directory is off or the
    search could not be completed, so the picker can say so."""
    cfg = settings()
    if not cfg["enable"]:
        raise DirectoryError("The Entra people search is not turned on.")
    text = _clean_query(query)
    if len(text) < _MIN_QUERY:
        return []
    found = _cached(("search", text.casefold()), cfg, lambda: _build_search(cfg, text))
    if found is None:
        raise DirectoryError("The people search could not reach Microsoft Entra. Type the person's "
                             "email instead, or try again in a minute.")
    return [dict(person) for person in found]


__all__ = [
    "SEARCH_LIMIT",
    "DirectoryError",
    "app_roles_for_object_id",
    "enabled",
    "object_ids_for",
    "principals_with_role",
    "reset_cache",
    "role_for_object_id",
    "role_for_principal",
    "role_holders",
    "search_people",
    "settings",
]
