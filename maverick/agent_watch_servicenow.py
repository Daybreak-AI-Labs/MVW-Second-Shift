"""ServiceNow platform check: the AI agents built in AI Agent Studio.

One watcher for ``agent_watch``, ``servicenow``, listing the AI agents of one
or more ServiceNow instances and fingerprinting how each is configured. It
reads four tables of each instance through the Table API:

* ``sn_aia_agent`` -- the agents themselves.
* ``sn_aia_agent_config`` -- each agent's settings record, which holds its
  active flag.
* ``sn_aia_version`` -- each agent's versions, which hold its instructions.
* ``sn_aia_agent_tool_m2m`` -- which tools each agent may use.

It signs in to each instance as an OAuth client (OAuth 2.0 client credentials
against the instance's own ``/oauth_token.do``) and takes the client id and
client secret from environment variables whose NAMES are in the settings
(``client_id_env``, ``client_secret_env``). A secret typed into the settings
is refused.

What it does not do. It only reads, and only the fixed calls the class names
in its docstring: nothing is created, changed, switched off or deleted. It
does not read what an agent did (execution plans, messages, logs), the tools
themselves, agentic workflows, triggers or the AI assets inventory. It accepts
an instance's own ``https://<instance>.service-now.com`` address only: a
company-branded custom URL is another name for that same address, so nothing
is lost by refusing it, and a client secret is then never sent anywhere else.
Role text, descriptions, scripts and instructions are hashed where they are
read and never kept.

Table and column names follow the ServiceNow pages cited beside each one.
Nothing here has been run against a live instance, and ServiceNow does not
say in so many words that these tables are served by the Table API, so only
what the check cannot work without is required: each record's ``sys_id``.
Every other column is optional: absent or empty is fine (the Table API leaves
out a column it does not know without saying so), but a value of the wrong
kind fails the run instead of being fingerprinted as if it were nothing.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from . import agent_watch
from .agent_watch import OBSERVED_SNAPSHOT, ObservedAgent, WatchConfigError, WatchError

#: An instance's own address. Customers may add company-branded custom URLs,
#: but each is an alias (CNAME) of this one, so this one always works:
#: https://www.servicenow.com/docs/r/platform-security/authentication/custom-url.html
_INSTANCE = re.compile(r"https://([A-Za-z0-9][A-Za-z0-9-]{0,62}\.service-now\.com)/?", re.IGNORECASE)
_INSTANCE_FORM = "https://<instance>.service-now.com"
_MAX_INSTANCES = 20
#: POST https://<instance>/oauth_token.do with grant_type, client_id,
#: client_secret and an optional scope:
#: https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials-grant-workflow.html
_TOKEN_URL = "https://{host}/oauth_token.do"
_SCOPE = re.compile(r"[A-Za-z0-9_.:-]{1,80}(?: [A-Za-z0-9_.:-]{1,80}){0,9}")
_SETTINGS = ("instances", "client_id_env", "client_secret_env", "scope")
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_]{1,40}")

#: GET /api/now/table/{tableName}: ``sysparm_fields`` (a column the table does
#: not have is ignored), ``sysparm_limit`` and ``sysparm_offset`` for paging,
#: ``ORDERBY`` in ``sysparm_query``, and the ``result`` list in the answer:
#: https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
_PAGE = 100
_LIST = ("https://{host}/api/now/table/{table}?sysparm_query=ORDERBYsys_id&sysparm_fields={fields}"
         "&sysparm_display_value=false&sysparm_exclude_reference_link=true"
         f"&sysparm_limit={_PAGE}")
#: The tables: https://www.servicenow.com/docs/r/intelligent-experiences/na-aia-reference.html
#: Their columns, from "Field Mapping (Fluent -> ServiceNow)" and "Coalesce
#: Keys" in the ServiceNow SDK reference: https://servicenow.github.io/sdk/api/aiagent-api
_AGENTS = ("sn_aia_agent", "sys_id,name,description,role,agent_type,channel,record_type,parent,"
                           "condition,context_processing_script,sys_updated_on")
_CONFIGS = ("sn_aia_agent_config", "sys_id,agent,active,public,run_as_user,advanced_mode,agent_learning")
_VERSIONS = ("sn_aia_version", "sys_id,target_id,version_name,version_number,state,instructions,condition")
_TOOLS = ("sn_aia_agent_tool_m2m", "sys_id,agent,tool,name,sys_updated_on")

#: "A unique 32-character GUID":
#: https://www.servicenow.com/docs/r/platform-administration/c_UniqueRecordIdentifier.html
_SYS_ID = re.compile(r"[0-9a-fA-F]{32}")
_TIMESTAMP = re.compile(r"[0-9][0-9T:.+\-Z ]{3,39}")
_FLAGS = {"true": True, "false": False}
_STATES = {True: "enabled", False: "disabled"}


class ServiceNowWatcher:
    """The AI agents of one or more ServiceNow instances.

    Settings, ``[agent_watch.servicenow]``: ``instances``, a list of 1 to 20
    addresses of the form ``https://<instance>.service-now.com``;
    ``client_id_env`` and ``client_secret_env``, each the name of an
    environment variable; and optionally ``scope``, the OAuth scope names to
    ask for, separated by spaces. Every instance listed is signed in to with
    the same client id and secret.

    Calls, per instance: one ``POST https://<instance>/oauth_token.do``
    (``grant_type=client_credentials``), then for each of ``sn_aia_agent``,
    ``sn_aia_agent_config``, ``sn_aia_version`` and ``sn_aia_agent_tool_m2m``:
    ``GET https://<instance>/api/now/table/<table>?sysparm_query=ORDERBYsys_id
    &sysparm_fields=<fixed column list>&sysparm_display_value=false
    &sysparm_exclude_reference_link=true&sysparm_limit=100&sysparm_offset=<n>``
    with ``n`` going up by 100 until a page comes back empty. ServiceNow
    applies the page size before its access rules, so a short page is not the
    end of a list; only an empty one is. Needs the inbound client-credentials
    grant switched on, and the OAuth client's application user given the role
    ``sn_aia.viewer`` (read access to the AI agent tables).

    The external id is ``<instance host>/<sys_id>``, because a clone or an
    update set keeps the same ``sys_id`` in every instance it lands in. The
    fingerprint covers, from the agent record, ``name``, ``agent_type``,
    ``channel``, ``record_type``, ``parent`` and hashes of ``role``,
    ``description``, ``condition`` and ``context_processing_script``; each
    settings record's ``active``, ``public``, ``run_as_user``,
    ``advanced_mode`` and ``agent_learning``; each version that is not a
    draft (``version_name``, ``version_number``, ``state`` and hashes of
    ``instructions`` and ``condition``); and each tool link (``tool``,
    ``name`` and its ``sys_updated_on``). ``state`` comes from ``active``,
    ``version`` is the one published version's name, and ``updated_at`` is
    the agent record's ``sys_updated_on``, which is shown but not
    fingerprinted. Versions can be edited, so the fingerprint is a snapshot.
    A settings, version or tool record that names no listed agent is passed
    over. One instance or table failing fails the whole run, so a missing
    table never reads as "nothing is set"."""

    name = "servicenow"

    def __init__(self, settings: dict) -> None:
        self._section = section = f"[agent_watch.{self.name}]"
        if "client_secret" in settings:
            raise WatchConfigError(
                f"{section} must not hold the client secret itself. Put it in an environment "
                "variable and give that variable's name in client_secret_env.")
        self._client_env = agent_watch.env_name(settings, "client_id_env", section)
        self._secret_env = agent_watch.env_name(settings, "client_secret_env", section)
        for key in settings:
            if key not in _SETTINGS:
                named = f": {key}" if isinstance(key, str) and _PLAIN_KEY.fullmatch(key) else ""
                raise WatchConfigError(f"{section} has a setting this check does not know{named}.")
        self._scope = _scope(settings, section)
        self._instances = _instances(settings, section)

    def list_agents(self) -> list[ObservedAgent]:
        reader = agent_watch.Reader()
        found: list[ObservedAgent] = []
        for host in self._instances:
            with _within(f"ServiceNow instance {host}"):
                token = self._token(host)
            agents = _table(reader, token, host, _AGENTS, _agent)
            settings = _by_agent(_table(reader, token, host, _CONFIGS, _setting))
            versions = _by_agent(_table(reader, token, host, _VERSIONS, _version))
            tools = _by_agent(_table(reader, token, host, _TOOLS, _tool))
            found.extend(
                self._observed(host, agent, settings.get(agent["sys_id"], []),
                               versions.get(agent["sys_id"], []), tools.get(agent["sys_id"], []))
                for agent in agents)
        return found

    def _token(self, host: str) -> str:
        """A bearer token for one instance. The two values are read now, so a
        replaced secret is picked up without a restart."""
        client = agent_watch.secret_named(self._client_env, f"client_id_env in {self._section}")
        secret = agent_watch.secret_named(self._secret_env, f"client_secret_env in {self._section}")
        return agent_watch.client_credentials_token(
            _TOKEN_URL.format(host=host), client_id=client, client_secret=secret, scope=self._scope)

    def _observed(self, host: str, agent: dict, settings: list[dict], versions: list[dict],
                  tools: list[str]) -> ObservedAgent:
        # A draft is not what runs, so editing one is not a change to the agent.
        live = [version for version in versions if version["state"] != "draft"]
        published = [version["label"] for version in live if version["state"] == "published"]
        active = {setting["active"] for setting in settings}
        parts = {**agent["parts"], "settings": sorted(setting["digest"] for setting in settings),
                 "versions": sorted(version["digest"] for version in live), "tools": sorted(tools)}
        return ObservedAgent(
            platform=self.name, external_id=f"{host}/{agent['sys_id']}", name=agent["name"] or "",
            version=published[0] if len(published) == 1 else "", updated_at=agent["updated"] or "",
            state=_STATES.get(active.pop(), "") if len(active) == 1 else "",
            fingerprint=agent_watch.fingerprint(parts), binding_strength=OBSERVED_SNAPSHOT)


def _scope(settings: dict, section: str) -> str:
    """The optional ``scope`` setting: scope names separated by single spaces,
    or "" to ask for none."""
    scope = settings.get("scope", "")
    if not isinstance(scope, str) or (scope and not _SCOPE.fullmatch(scope)):
        raise WatchConfigError(f"scope in {section} must be scope names (letters, digits and "
                               "_ . : -) separated by single spaces.")
    return scope


def _instances(settings: dict, section: str) -> list[str]:
    """The instance hosts to read, from the list setting ``instances``. Every
    entry must be an instance's own address; an entry is never repeated in a
    message, in case it carries a credential."""
    entries = settings.get("instances")
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_INSTANCES:
        raise WatchConfigError(f"{section} needs instances: a list of 1 to {_MAX_INSTANCES} "
                               f"addresses of the form {_INSTANCE_FORM}.")
    hosts: list[str] = []
    for position, entry in enumerate(entries, start=1):
        match = _INSTANCE.fullmatch(entry.strip()) if isinstance(entry, str) else None
        if match is None:
            raise WatchConfigError(f"Entry {position} of instances in {section} is not an address "
                                   f"of the form {_INSTANCE_FORM}.")
        host = match.group(1).lower()
        if host in hosts:
            raise WatchConfigError(f"Entry {position} of instances in {section} repeats an earlier one.")
        hosts.append(host)
    return hosts


@contextmanager
def _within(where: str) -> Iterator[None]:
    """Say which instance and table a failure belongs to."""
    try:
        yield
    except WatchError as e:
        raise WatchError(f"{where}: {e}") from None


def _table(reader: agent_watch.Reader, token: str, host: str, table: tuple[str, str],
           keep: Callable[[dict], Any]) -> list:
    """One table of one instance, read to its end. Each record goes through
    ``keep``, which holds on to what the check needs and nothing else."""
    name, fields = table
    url = _LIST.format(host=host, table=name, fields=fields)
    with _within(f"ServiceNow instance {host}, table {name}"):
        rows = reader.records(f"{url}&sysparm_offset=0", bearer=token, items="result",
                              next_url=_by_offset(url))
        return [keep(row) for row in rows]


def _by_offset(first_url: str) -> Callable[[dict, str], str | None]:
    """Offset paging for a Table API list: the next address is the first one
    plus the next ``sysparm_offset``. The list ends at an empty page, never at
    a short one, because ServiceNow applies ``sysparm_limit`` before its
    access rules. A page that holds nothing new is a repeat, and an error."""
    seen: set[str] = set()
    offset = 0

    def next_url(page: dict, _url: str) -> str | None:
        nonlocal offset
        ids = [row.get("sys_id") for row in page["result"]]
        if not ids:
            return None
        if not all(isinstance(sys_id, str) and sys_id for sys_id in ids):
            raise agent_watch.unexpected_answer()
        if seen.issuperset(ids):
            raise WatchError("ServiceNow sent records it had already sent (a repeat), so the "
                             "check stopped and nothing from it was used.")
        seen.update(ids)
        offset += _PAGE
        return f"{first_url}&sysparm_offset={offset}"
    return next_url


def _by_agent(kept: list[tuple[str | None, Any]]) -> dict[str, list]:
    """Settings, version or tool records grouped under the agent each names.
    One that names no agent belongs to something else and is left out."""
    grouped: dict[str, list] = {}
    for owner, value in kept:
        if owner is not None:
            grouped.setdefault(owner, []).append(value)
    return grouped


def _text(row: dict, key: str) -> str | None:
    """``row[key]`` as text, or ``None`` when it is absent or empty (the Table
    API sends an empty column as ""). Any other kind of value fails the run:
    a column that changed shape must not be fingerprinted as if it were empty."""
    value = row.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise agent_watch.unexpected_answer()
    return value


def _flag(row: dict, key: str) -> bool | None:
    """A true/false column, which the Table API sends as "true" or "false"."""
    value = _text(row, key)
    if value is not None and value not in _FLAGS:
        raise agent_watch.unexpected_answer()
    return None if value is None else _FLAGS[value]


def _reference(row: dict, key: str) -> str | None:
    """A reference column: the ``sys_id`` of the record it points to."""
    value = _text(row, key)
    return None if value is None else _sys_id(value)


def _sys_id(value: Any) -> str:
    if not isinstance(value, str) or not _SYS_ID.fullmatch(value):
        raise agent_watch.unexpected_answer()
    return value.lower()


def _timestamp(row: dict, key: str) -> str | None:
    value = _text(row, key)
    if value is not None and not _TIMESTAMP.fullmatch(value):
        raise agent_watch.unexpected_answer()
    return value


def _hashed(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _agent(row: dict) -> dict:
    """What is kept of one ``sn_aia_agent`` record: its id, what is shown of
    it, and its share of the fingerprint. Long text is hashed here."""
    name = _text(row, "name")
    parts = {"name": name, "agent_type": _text(row, "agent_type"), "channel": _text(row, "channel"),
             "record_type": _text(row, "record_type"), "parent": _reference(row, "parent"),
             **{key: _hashed(_text(row, key))
                for key in ("role", "description", "condition", "context_processing_script")}}
    return {"sys_id": _sys_id(row.get("sys_id")), "name": name,
            "updated": _timestamp(row, "sys_updated_on"), "parts": parts}


def _setting(row: dict) -> tuple[str | None, dict]:
    """One ``sn_aia_agent_config`` record: the agent it belongs to, its active
    flag, and a digest of the settings that are fingerprinted."""
    active = _flag(row, "active")
    parts = {"active": active, "run_as_user": _reference(row, "run_as_user"),
             **{key: _flag(row, key) for key in ("public", "advanced_mode", "agent_learning")}}
    return _reference(row, "agent"), {"active": active, "digest": agent_watch.fingerprint(parts)}


def _version(row: dict) -> tuple[str | None, dict]:
    """One ``sn_aia_version`` record: what it is a version of, its state
    ("draft", "committed", "published" or "withdrawn"), a label to show, and
    a digest. The instructions are hashed here and not kept."""
    name, number = _text(row, "version_name"), _text(row, "version_number")
    state = (_text(row, "state") or "").strip().lower()
    parts = {"version_name": name, "version_number": number, "state": state,
             "instructions": _hashed(_text(row, "instructions")),
             "condition": _hashed(_text(row, "condition"))}
    return _reference(row, "target_id"), {"state": state, "label": name or number or "",
                                          "digest": agent_watch.fingerprint(parts)}


def _tool(row: dict) -> tuple[str | None, str]:
    """One ``sn_aia_agent_tool_m2m`` record: the agent, and a digest of the
    tool it links to. How the tool may be used is not read column by column;
    a change to it moves the link's ``sys_updated_on``."""
    parts = {"tool": _reference(row, "tool"), "name": _text(row, "name"),
             "sys_updated_on": _timestamp(row, "sys_updated_on")}
    return _reference(row, "agent"), agent_watch.fingerprint(parts)


agent_watch.register(ServiceNowWatcher.name, ServiceNowWatcher)

__all__ = [
    "ServiceNowWatcher",
]
