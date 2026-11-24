"""Microsoft platform checks: Entra Agent ID, Foundry Agent Service and
Copilot Studio.

Three watchers for ``agent_watch``, each listing the agents one Microsoft
service knows about and fingerprinting how each is configured:

* ``entra_agent_id`` -- the agent identities in a Microsoft Entra tenant,
  through Microsoft Graph v1.0.
* ``foundry`` -- the agents of one or more Microsoft Foundry projects, each
  with its latest version, through the Foundry Agent Service.
* ``copilot_studio`` -- the agents of one or more Power Platform
  environments, from the Dataverse ``bot`` table through the Dataverse Web API.

All three sign in the same way, as an app registration with a client secret
(OAuth 2.0 client credentials against ``login.microsoftonline.com``), and take
the tenant id, client id and client secret from environment variables whose
NAMES are in the settings (``tenant_id_env``, ``client_id_env``,
``client_secret_env``). A secret typed into the settings is refused.

What it does not do. It only reads, and only the fixed calls each class names
in its docstring: nothing is created, changed, disabled or deleted. The one
exception is ``EntraAgentIdWatcher.switch``, which an administrator may turn on
for Entra Agent ID alone with ``allow_switch_off = true`` (see
``agent_watch_switch``); it is never called by a check. It does
not use the Microsoft Agent 365 registry (the Graph "packages" API), which
needs an Agent 365 licence, and it does not read what an agent did, only what
it is. It covers the Microsoft public cloud only: the sign-in, Graph, Foundry
and Dataverse addresses are fixed to their public-cloud hosts, so a sovereign
or government cloud is refused in the settings. Instructions, tool settings and
any other large value are hashed where they are read and never kept.

Field names follow the Microsoft documentation cited beside each watcher.
Nothing here has been run against a live tenant, so only what a check cannot
work without is required: an agent's identifier, for Foundry the latest
version and its definition, and for Copilot Studio the modified time. Every
other field is optional: absent is fine, but a value of the wrong kind fails
the run instead of being fingerprinted as if it were nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from . import agent_watch, agent_watch_changes
from .agent_watch import (
    IMMUTABLE_REVISION,
    OBSERVED_SNAPSHOT,
    ObservedAgent,
    WatchConfigError,
    WatchError,
)

#: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}")

_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_TIMESTAMP = re.compile(r"[0-9][0-9T:.+\-Z ]{3,39}")
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_]{1,40}")
_CREDENTIAL_KEYS = ("tenant_id_env", "client_id_env", "client_secret_env")
#: The most project endpoints or environments one watcher reads.
_MAX_PLACES = 20
_MAX_CURSOR = 200


@dataclass(frozen=True)
class _Credentials:
    """The app registration a watcher signs in as, by environment-variable name."""

    section: str
    tenant_env: str
    client_env: str
    secret_env: str

    def token(self, scope: str) -> str:
        """A bearer token for ``scope``. The three values are read now, so a
        rotated secret is picked up without a restart."""
        tenant, client, secret = (
            agent_watch.secret_named(variable, f"{key} in {self.section}")
            for key, variable in zip(_CREDENTIAL_KEYS,
                                     (self.tenant_env, self.client_env, self.secret_env), strict=True))
        # The tenant id becomes part of the sign-in address, so it must be
        # nothing but a directory id or a domain name.
        if not _TENANT.fullmatch(tenant):
            raise WatchError(f"The value named by tenant_id_env in {self.section} is not a "
                             "directory (tenant) id or domain name.")
        if not _CLIENT_ID.fullmatch(client):
            raise WatchError(f"The value named by client_id_env in {self.section} is not an "
                             "application (client) id.")
        return agent_watch.client_credentials_token(
            _TOKEN_URL.format(tenant=tenant), client_id=client, client_secret=secret, scope=scope)


def _credentials(settings: dict, section: str, *, also: tuple[str, ...] = ()) -> _Credentials:
    """The credential settings of one watcher's table, which may hold only
    those and the keys in ``also``."""
    if "client_secret" in settings:
        raise WatchConfigError(
            f"{section} must not hold the client secret itself. Put it in an environment "
            "variable and give that variable's name in client_secret_env.")
    found = _Credentials(section, *(agent_watch.env_name(settings, key, section)
                                    for key in _CREDENTIAL_KEYS))
    for key in settings:
        if key not in _CREDENTIAL_KEYS and key not in also:
            named = f": {key}" if isinstance(key, str) and _PLAIN_KEY.fullmatch(key) else ""
            raise WatchConfigError(f"{section} has a setting this check does not know{named}.")
    return found


def _places(settings: dict, key: str, section: str, pattern: re.Pattern[str], form: str,
            label: Callable[[re.Match[str]], tuple[str, str]]) -> list[tuple[str, str]]:
    """The addresses a watcher reads, from the list setting ``key``: each as
    (label, base address). Every entry must match the one documented form; an
    entry is never repeated in a message, in case it carries a credential."""
    entries = settings.get(key)
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_PLACES:
        raise WatchConfigError(f"{section} needs {key}: a list of 1 to {_MAX_PLACES} addresses "
                               f"of the form {form}.")
    places: list[tuple[str, str]] = []
    for position, entry in enumerate(entries, start=1):
        match = pattern.fullmatch(entry.strip()) if isinstance(entry, str) else None
        if match is None:
            raise WatchConfigError(f"Entry {position} of {key} in {section} is not an address of "
                                   f"the form {form}.")
        place = label(match)
        if place in places:
            raise WatchConfigError(f"Entry {position} of {key} in {section} repeats an earlier one.")
        places.append(place)
    return places


@contextmanager
def _within(where: str) -> Iterator[None]:
    """Say which project or environment a failure belongs to."""
    try:
        yield
    except WatchError as e:
        raise WatchError(f"{where}: {e}") from None


def _optional(row: dict, key: str, kind: type) -> Any:
    """``row[key]`` when it is a ``kind``, ``None`` when it is absent. Any
    other value fails the run: a field that changed shape must not be
    fingerprinted as if it were empty."""
    value = row.get(key)
    if value is None:
        return None
    # True and False are whole numbers to Python; they are not to a platform.
    if not isinstance(value, kind) or (isinstance(value, bool) and kind is not bool):
        raise agent_watch.unexpected_answer()
    return value


def _guid(row: dict, key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not _GUID.fullmatch(value):
        raise agent_watch.unexpected_answer()
    return value.lower()


def _timestamp(row: dict, key: str) -> str | None:
    value = _optional(row, key, str)
    if value is not None and not _TIMESTAMP.fullmatch(value):
        raise agent_watch.unexpected_answer()
    return value


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


#: https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0
_GRAPH_AGENT_IDENTITIES = "https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_GRAPH_AGENT_IDENTITY_BASE = "https://graph.microsoft.com/v1.0/servicePrincipals"
#: https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0
_IDENTITY_TEXT_FIELDS = ("displayName", "agentIdentityBlueprintId", "disabledByMicrosoftStatus",
                         "servicePrincipalType")


class EntraAgentIdWatcher:
    """The agent identities in a Microsoft Entra tenant.

    Settings, ``[agent_watch.entra_agent_id]``: ``tenant_id_env``,
    ``client_id_env`` and ``client_secret_env``, each the name of an
    environment variable; and optionally ``allow_switch_off`` (true or false,
    default false), which lets an administrator disable and re-enable an
    identity from Second Shift through ``switch`` (see below).

    Calls: ``GET https://graph.microsoft.com/v1.0/servicePrincipals/
    microsoft.graph.agentIdentity`` with no query options, then each
    ``@odata.nextLink`` exactly as returned (https://learn.microsoft.com/en-us/graph/paging).
    Needs the Microsoft Graph application permission ``AgentIdentity.Read.All``
    with admin consent; the token scope is ``https://graph.microsoft.com/.default``.

    Each identity's ``id`` is its external id. The fingerprint covers
    ``displayName``, ``accountEnabled``, ``agentIdentityBlueprintId``,
    ``disabledByMicrosoftStatus`` and ``servicePrincipalType``; ``tags`` are
    left out because they also change when the blueprint's tags do. ``state``
    comes from ``accountEnabled``. The resource has no version and no
    modified time, so those stay empty and the fingerprint is a snapshot. It
    does not read what an identity is allowed to do (role assignments,
    permission grants), its owners or its sponsors."""

    name = "entra_agent_id"

    def __init__(self, settings: dict) -> None:
        section = f"[agent_watch.{self.name}]"
        self._credentials = _credentials(settings, section, also=("allow_switch_off",))
        allowed = settings.get("allow_switch_off", False)
        if not isinstance(allowed, bool):
            raise WatchConfigError(f"allow_switch_off in {section} must be true or false.")
        self.allow_switch_off = allowed

    def switch(self, external_id: str, *, enabled: bool) -> None:
        """Disable (``enabled=False``) or re-enable one agent identity: ``PATCH
        https://graph.microsoft.com/v1.0/servicePrincipals/{id}/microsoft.graph.agentIdentity``
        with ``{"accountEnabled": <bool>}``, answered ``204 No Content``
        (https://learn.microsoft.com/en-us/graph/api/agentidentity-update?view=graph-rest-1.0).
        ``accountEnabled`` is the documented property: when false no one can
        sign in to the identity
        (https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0).
        The application permission is ``AgentIdentity.EnableDisable.All``
        ("Enable or disable agent identities", admin consent required;
        https://learn.microsoft.com/en-us/graph/permissions-reference).

        One request, never retried. ``external_id`` must be an identity id
        (a GUID): it is the only part of the address that varies. Raises
        :class:`WatchError`, worded without anything from Microsoft's answer,
        when the request is not accepted."""
        if not self.allow_switch_off:
            raise WatchError("Switching agents off is not allowed in this check's settings.")
        if not isinstance(external_id, str) or not _GUID.fullmatch(external_id):
            raise WatchError("The platform id kept for this agent is not an agent identity id.")
        token = self._credentials.token(_GRAPH_SCOPE)
        status, _body = agent_watch._request(
            "PATCH", f"{_GRAPH_AGENT_IDENTITY_BASE}/{external_id.lower()}/microsoft.graph.agentIdentity",
            headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
            timeout=agent_watch.limits().timeout_seconds, max_bytes=64 * 1024,
            json_body={"accountEnabled": enabled}, ok=(200, 204))
        if status in (200, 204):
            return
        if status == 401:
            agent_watch._forget_token(token)
        raise WatchError(_switch_refusal(status))

    def list_agents(self) -> list[ObservedAgent]:
        token = self._credentials.token(_GRAPH_SCOPE)
        rows = agent_watch.Reader().records(_GRAPH_AGENT_IDENTITIES, bearer=token, items="value",
                                            next_url=agent_watch.odata_next)
        return [self._identity(row) for row in rows]

    def _identity(self, row: dict) -> ObservedAgent:
        enabled = _optional(row, "accountEnabled", bool)
        parts = {key: _optional(row, key, str) for key in _IDENTITY_TEXT_FIELDS}
        return ObservedAgent(
            platform=self.name, external_id=_guid(row, "id"), name=parts["displayName"] or "",
            state={True: "enabled", False: "disabled"}.get(enabled, ""),
            fingerprint=agent_watch.fingerprint({**parts, "accountEnabled": enabled}),
            binding_strength=OBSERVED_SNAPSHOT,
            details=agent_watch_changes.describe(self.name, {
                "name": parts["displayName"], "enabled": enabled,
                "blueprint": parts["agentIdentityBlueprintId"],
                "disabled_by_microsoft": parts["disabledByMicrosoftStatus"],
                "identity_type": parts["servicePrincipalType"]}))


def _switch_refusal(status: int) -> str:
    """Why Microsoft did not take a switch-off or switch-on, in plain words."""
    if status == 401:
        return ("Microsoft did not accept this check's sign-in (HTTP 401). Check the client id and "
                "secret, and that the secret has not expired.")
    if status == 403:
        return ("Microsoft refused the change (HTTP 403). The app registration probably has not been "
                "granted the Microsoft Graph application permission AgentIdentity.EnableDisable.All "
                "with administrator consent.")
    if status == 404:
        return ("Microsoft says this agent identity does not exist (HTTP 404). It may have been "
                "deleted, or the platform link on this agent is wrong.")
    if status == 429:
        return "Microsoft is limiting requests at the moment (HTTP 429). Try again in a few minutes."
    if 300 <= status < 400:
        return f"Microsoft answered with a redirect (HTTP {status}), which is not followed."
    return f"Microsoft answered with HTTP {status}, which was not expected."


#: https://learn.microsoft.com/en-us/azure/foundry/agents/quickstarts/prompt-agent
_FOUNDRY_ENDPOINT = re.compile(
    r"https://([A-Za-z0-9][A-Za-z0-9-]{0,62})\.services\.ai\.azure\.com"
    r"/api/projects/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/?", re.IGNORECASE)
_FOUNDRY_FORM = "https://<resource>.services.ai.azure.com/api/projects/<project>"
#: https://learn.microsoft.com/en-us/azure/foundry/concepts/authentication-authorization-foundry
_FOUNDRY_SCOPE = "https://ai.azure.com/.default"
#: The list takes ``limit`` 1 to 100; pages are kept small because each agent
#: comes with its whole definition.
_FOUNDRY_PAGE = 50
_FOUNDRY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class FoundryWatcher:
    """The agents of one or more Microsoft Foundry projects, each with its
    latest version.

    Settings, ``[agent_watch.foundry]``: the three credential names, and
    ``endpoints``, a list of 1 to 20 project endpoints of the form
    ``https://<resource>.services.ai.azure.com/api/projects/<project>``.

    Calls, per project: ``GET <endpoint>/agents?api-version=v1&limit=50&order=asc``,
    then the same address with ``&after=<cursor>`` while the answer says
    ``has_more`` (the cursor is ``last_id``, or the last agent's ``id``).
    Reference: "List agents" in the Foundry REST API reference,
    https://ai.azure.com/api-reference/llm/agents/list-agents.md, which is
    where https://learn.microsoft.com/en-us/azure/foundry/reference/foundry-project
    leads. Needs an Azure role on the Foundry resource or project that can
    read agents (the built-in "Foundry User", formerly "Azure AI User"); the
    token scope is ``https://ai.azure.com/.default``.

    Each list item carries ``versions.latest``, so no call is made per agent.
    The external id is ``<resource>/<project>/<agent name>``. The fingerprint
    covers the latest version's ``version`` id and, from its ``definition``,
    ``kind``, ``model``, a hash of ``instructions`` and a hash of each tool;
    versions are immutable, so the binding is "immutable_provider_revision".
    ``updated_at`` is when that version was created, ``state`` the agent's
    ``state``. One project failing fails the whole run, so a missing project
    never reads as "its agents are gone"."""

    name = "foundry"

    def __init__(self, settings: dict) -> None:
        section = f"[agent_watch.{self.name}]"
        self._credentials = _credentials(settings, section, also=("endpoints",))
        self._projects = _places(settings, "endpoints", section, _FOUNDRY_ENDPOINT, _FOUNDRY_FORM,
                                 _foundry_project)

    def list_agents(self) -> list[ObservedAgent]:
        token = self._credentials.token(_FOUNDRY_SCOPE)
        reader = agent_watch.Reader()
        found: list[ObservedAgent] = []
        for label, base in self._projects:
            url = f"{base}/agents?api-version=v1&limit={_FOUNDRY_PAGE}&order=asc"
            with _within(f"Foundry project {label}"):
                rows = reader.records(url, bearer=token, items="data", next_url=_after(url))
                found.extend(self._agent(row, label) for row in rows)
        return found

    def _agent(self, row: dict, label: str) -> ObservedAgent:
        name = row.get("name")
        latest = _optional(_optional(row, "versions", dict) or {}, "latest", dict)
        if not isinstance(name, str) or not _FOUNDRY_NAME.fullmatch(name) or latest is None:
            raise agent_watch.unexpected_answer()
        version = _version(latest.get("version"))
        definition = latest.get("definition")
        if not version or not isinstance(definition, dict):
            raise agent_watch.unexpected_answer()
        state = row.get("state")
        return ObservedAgent(
            platform=self.name, external_id=f"{label}/{name}", name=name, version=version,
            updated_at=_unix_time(latest.get("created_at")),
            state=state if state in ("enabled", "disabled") else "",
            fingerprint=agent_watch.fingerprint({"version": version, **_defined(definition)}),
            binding_strength=IMMUTABLE_REVISION,
            details=agent_watch_changes.describe(self.name, {
                "name": name, "version": version,
                "state": state if state in ("enabled", "disabled") else None,
                **_described(definition)}))


def _version(value: Any) -> str:
    """A version id as text: documented as a string, and a bare number is
    accepted too. "" for anything else."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    return str(value).strip()


def _foundry_project(match: re.Match[str]) -> tuple[str, str]:
    resource, project = match.group(1).lower(), match.group(2)
    return f"{resource}/{project}", f"https://{resource}.services.ai.azure.com/api/projects/{project}"


def _after(first_url: str) -> Callable[[dict, str], str | None]:
    """Cursor paging for a Foundry list: the next address is the first one plus
    ``after=<cursor>``. The cursor comes from the platform, so it is only ever
    sent as one encoded query value."""
    def next_url(page: dict, _url: str) -> str | None:
        more = page.get("has_more")
        if more is False:
            return None
        cursor = page.get("last_id")
        if cursor is None and page.get("data"):
            cursor = page["data"][-1].get("id")
        if more is not True or not isinstance(cursor, str) or not 0 < len(cursor) <= _MAX_CURSOR:
            raise agent_watch.unexpected_answer()
        return f"{first_url}&after={quote(cursor, safe='')}"
    return next_url


def _defined(definition: dict) -> dict:
    """What a version's definition contributes to the fingerprint. The
    instructions and each tool's settings are hashed here and not kept; tools
    are hashed one by one and sorted, so their order does not matter."""
    instructions = _optional(definition, "instructions", str)
    tools = _optional(definition, "tools", list) or []
    return {"kind": _optional(definition, "kind", str), "model": _optional(definition, "model", str),
            "instructions": None if instructions is None else _sha256(instructions),
            "tools": sorted(_sha256(_canonical(tool)) for tool in tools)}


def _described(definition: dict) -> dict:
    """What a version's definition contributes to its description: the model,
    the kind, each tool's short label and a digest of that tool's settings, and
    a digest of the instructions. Nothing the author wrote is kept."""
    instructions = _optional(definition, "instructions", str)
    labels: dict[str, str] = {}
    for tool in _optional(definition, "tools", list) or []:
        label = _tool_label(tool)
        while label in labels:
            label += "#"
        labels[label] = agent_watch_changes.digest(_sha256(_canonical(tool))) or ""
    return {"kind": _optional(definition, "kind", str), "model": _optional(definition, "model", str),
            "instructions": agent_watch_changes.digest(None if instructions is None else _sha256(instructions)),
            "tools": list(labels), "tool_settings": labels}


def _tool_label(tool: Any) -> str:
    """A tool as a short label: its type, and its name or MCP server label when
    it has one (``function:send_email``, ``mcp:github``, ``code_interpreter``).
    The tool types and the name and ``server_label`` fields are those in
    https://learn.microsoft.com/azure/foundry/agents/how-to/tools/toolbox
    (tool names) and the Foundry agent reference. Only these two short fields
    are read; descriptions and settings are not."""
    if not isinstance(tool, dict):
        return "tool"
    kind = tool.get("type") if isinstance(tool.get("type"), str) else "tool"
    for key in ("name", "server_label"):
        named = tool.get(key)
        if isinstance(named, str) and named.strip():
            return f"{kind}:{named.strip()}"
    return kind


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        raise agent_watch.unexpected_answer() from None


def _unix_time(value: Any) -> str:
    """A Unix timestamp as UTC text, or "" when there is none."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < 10 ** 11:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


#: The parts of an environment address:
#: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/compose-http-requests-handle-errors
_DATAVERSE_ENVIRONMENT = re.compile(
    r"https://([A-Za-z0-9][A-Za-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com)/?", re.IGNORECASE)
_DATAVERSE_FORM = "https://<environment>.crm.dynamics.com (the region part may be crm2, crm4, ...)"
#: Columns of the ``bot`` table:
#: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/bot
_BOTS_QUERY = ("/api/data/v9.2/bots?$select=botid,name,schemaname,publishedon,modifiedon,"
               "statecode,statuscode&$orderby=botid")
#: Paging: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/query/page-results
_DATAVERSE_HEADERS = {"OData-MaxVersion": "4.0", "OData-Version": "4.0", "If-None-Match": "null",
                      "Prefer": "odata.maxpagesize=200"}
#: ``statecode`` choices of the ``bot`` table: 0 Active, 1 Inactive.
_BOT_STATES = {0: "enabled", 1: "disabled"}


class CopilotStudioWatcher:
    """The Copilot Studio agents of one or more Power Platform environments.

    Settings, ``[agent_watch.copilot_studio]``: the three credential names,
    and ``environments``, a list of 1 to 20 environment addresses of the form
    ``https://<environment>.crm.dynamics.com`` (``crm4``, ``crm11`` and so on
    for other regions).

    Calls, per environment: ``GET <environment>/api/data/v9.2/bots?$select=
    botid,name,schemaname,publishedon,modifiedon,statecode,statuscode&$orderby=
    botid`` with the Web API's standard headers and ``Prefer:
    odata.maxpagesize=200``, then each ``@odata.nextLink`` exactly as returned.
    Needs the app registration added to each environment as an application
    user with a security role that can read the Agent (``bot``) table; each
    environment is its own resource, so the token scope is
    ``<environment address>/.default`` (https://learn.microsoft.com/en-us/power-apps/developer/data-platform/authenticate-oauth).

    The external id is ``<environment host>/<botid>``, because a solution
    import keeps the same ``botid`` in every environment it lands in. The
    fingerprint covers ``publishedon``, ``modifiedon``, ``statecode`` and
    ``statuscode``; ``state`` comes from ``statecode`` and ``updated_at`` is
    ``modifiedon``. The table has no version id, so the fingerprint is a
    snapshot. The large ``configuration`` column is not read at all: a change
    to it moves ``modifiedon``. Topics, knowledge and actions live in other
    tables that are not read, so an edit to them shows only once the agent is
    published. One environment failing fails the whole run."""

    name = "copilot_studio"

    def __init__(self, settings: dict) -> None:
        section = f"[agent_watch.{self.name}]"
        self._credentials = _credentials(settings, section, also=("environments",))
        self._environments = [host for host, _base in _places(
            settings, "environments", section, _DATAVERSE_ENVIRONMENT, _DATAVERSE_FORM,
            lambda match: (match.group(1).lower(), ""))]

    def list_agents(self) -> list[ObservedAgent]:
        reader = agent_watch.Reader()
        found: list[ObservedAgent] = []
        for host in self._environments:
            with _within(f"Environment {host}"):
                token = self._credentials.token(f"https://{host}/.default")
                rows = reader.records(f"https://{host}{_BOTS_QUERY}", bearer=token, items="value",
                                      next_url=agent_watch.odata_next, headers=_DATAVERSE_HEADERS)
                found.extend(self._bot(row, host) for row in rows)
        return found

    def _bot(self, row: dict, host: str) -> ObservedAgent:
        state = _optional(row, "statecode", int)
        modified = _timestamp(row, "modifiedon")
        if modified is None:
            # Dataverse stamps every row; without it a change could go unseen.
            raise agent_watch.unexpected_answer()
        parts = {"publishedon": _timestamp(row, "publishedon"), "modifiedon": modified,
                 "statecode": state, "statuscode": _optional(row, "statuscode", int)}
        name = _optional(row, "name", str) or _optional(row, "schemaname", str) or ""
        return ObservedAgent(
            platform=self.name, external_id=f"{host}/{_guid(row, 'botid')}", name=name,
            updated_at=modified, state=_BOT_STATES.get(state, ""),
            fingerprint=agent_watch.fingerprint(parts), binding_strength=OBSERVED_SNAPSHOT,
            details=agent_watch_changes.describe(self.name, {
                "name": name, "state": _BOT_STATES.get(state), "status_code": parts["statuscode"],
                "published": parts["publishedon"], "modified": modified}))


agent_watch.register(EntraAgentIdWatcher.name, EntraAgentIdWatcher)
agent_watch.register(FoundryWatcher.name, FoundryWatcher)
agent_watch.register(CopilotStudioWatcher.name, CopilotStudioWatcher)

__all__ = [
    "CopilotStudioWatcher",
    "EntraAgentIdWatcher",
    "FoundryWatcher",
]
