"""Workday platform check: the agent definitions in a tenant's Agent System of
Record.

One watcher for ``agent_watch``, ``workday``, listing the agent definitions
registered in one Workday tenant and fingerprinting how each is set up. It
makes one call to the Agent System of Record (ASOR) API through Workday's
Agent Gateway.

It signs in as a Workday API client for integrations, with the refresh token
of an integration system user (OAuth 2.0 refresh-token grant against the
gateway's token address). Workday documents no client-credentials sign-in for
this API, so ``agent_watch.client_credentials_token`` cannot be used here; the
sign-in below is this module's own, sent through the same guarded request the
framework uses. The client id, client secret and refresh token come from
environment variables whose NAMES are in the settings (``client_id_env``,
``client_secret_env``, ``refresh_token_env``). A secret typed into the
settings is refused, and the access token is used for one run and never kept.

What it does not do. It only reads, and only the two fixed calls the class
names in its docstring: nothing is registered, changed, switched off or
deleted. Workday's API says what an agent is, not whether it is switched on:
activation, the on/off state of each skill and the security groups an agent
is available to live in the Agent Management Hub and cannot be read, so
``state`` is always empty. There is no "last changed" time and nothing about
what an agent did. Descriptions, skills and resource lists are hashed where
they are read and never kept.

Field names follow the Workday pages cited beside each one. Nothing here has
been run against a live tenant. The list has no documented paging, so one
answer must be the whole list: its ``total`` has to equal the number of
definitions sent, and anything else fails the run. Apart from that, only each
definition's ``id`` is required. Every other field is optional: absent is
fine, but a value of the wrong kind fails the run instead of being
fingerprinted as if it were nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from . import agent_watch, agent_watch_changes
from .agent_watch import OBSERVED_SNAPSHOT, ObservedAgent, WatchConfigError, WatchError

#: "Regional Availability of Agent Gateway": one public endpoint per region,
#: https://<region>.agent.workday.com:
#: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/workday-agent-gateway-for-partner-agents.html
_REGIONS = ("us", "eu", "uk", "ca", "au", "sg", "in", "jp")
#: The tenant alias goes into the sign-in address and a header, so it must be
#: nothing but a name.
_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
#: "Token Endpoint: https://us.agent.workday.com/auth/oauth2/<Tenant_Name>/token":
#: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/external-agents/register-and-authenticate-external-agents.html
#: The refresh-token request (grant_type, refresh_token, client_id,
#: client_secret) of an integration system user's API client:
#: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/external-agents/connect-custom-agents-to-external-agents-using-a2a.html
_TOKEN_URL = "https://{region}.agent.workday.com/auth/oauth2/{tenant}/token"
_SECRET_KEYS = ("client_id_env", "client_secret_env", "refresh_token_env")
_SETTINGS = ("region", "tenant", *_SECRET_KEYS)
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_]{1,40}")
_MAX_TOKEN_BYTES = 64 * 1024
_TOKEN_TEXT = re.compile(r"[\x21-\x7e]{1,16384}")

#: "REST API Endpoint: https://us.agent.workday.com/asor/v1/agentDefinition",
#: with the headers Authorization and wd-agent-tenant-alias (same page as the
#: token endpoint). GET /agentDefinition answers {"total", "data"}:
#: https://workday.github.io/asor/versions/v1.2.json
_DEFINITIONS_URL = "https://{region}.agent.workday.com/asor/v1/agentDefinition"
#: A Workday id (32 hex characters) or a reference id ("Type=Value").
_ID = re.compile(r"[A-Za-z0-9_.=:-]{1,100}")
_TEXT_FIELDS = ("name", "version", "url", "externalAgentID", "externalTenantID")
_CAPABILITIES = ("pushNotifications", "stateTransitionHistory", "streaming")
_LIST_FIELDS = ("defaultInputModes", "defaultOutputModes", "skills", "workdayConfig")


class WorkdayWatcher:
    """The agent definitions registered in one Workday tenant.

    Settings, ``[agent_watch.workday]``: ``region``, the Agent Gateway region
    that hosts the tenant (``us``, ``eu``, ``uk``, ``ca``, ``au``, ``sg``,
    ``in`` or ``jp``); ``tenant``, the tenant alias (normally the tenant
    name); and ``client_id_env``, ``client_secret_env`` and
    ``refresh_token_env``, each the name of an environment variable.

    Calls: one ``POST https://<region>.agent.workday.com/auth/oauth2/<tenant>/token``
    (``grant_type=refresh_token``), then one ``GET
    https://<region>.agent.workday.com/asor/v1/agentDefinition`` with the
    header ``wd-agent-tenant-alias: <tenant>``. Needs an API client for
    integrations with the scope *Agent System of Record*, and an integration
    system user, holding the refresh token, whose security group can view the
    *Setup: Agents* domain.

    Each definition's ``id`` is the last part of its external id,
    ``<tenant>/<id>``. The fingerprint covers ``name``, ``version``, ``url``,
    ``externalAgentID``, ``externalTenantID``, the ``provider`` and
    ``platform`` ids, ``capabilities``, ``supportsAuthenticatedExtendedCard``
    and hashes of ``description``, ``defaultInputModes``,
    ``defaultOutputModes``, ``skills`` and ``workdayConfig`` (which Workday
    resources each skill may use, and whether it runs on its own or for a
    person). ``overview``, ``iconUrl`` and ``documentationUrl`` are left out.
    Registering the same name, provider and version again changes a
    definition in place, so the fingerprint is a snapshot. ``version`` is the
    provider's own label; ``state`` and ``updated_at`` stay empty because the
    API has neither. The same ``id`` listed twice fails the run."""

    name = "workday"

    def __init__(self, settings: dict) -> None:
        self._section = section = f"[agent_watch.{self.name}]"
        if "client_secret" in settings or "refresh_token" in settings:
            raise WatchConfigError(
                f"{section} must not hold the client secret or the refresh token itself. Put each "
                "in an environment variable and give the variables' names in client_secret_env "
                "and refresh_token_env.")
        self._variables = [agent_watch.env_name(settings, key, section) for key in _SECRET_KEYS]
        for key in settings:
            if key not in _SETTINGS:
                named = f": {key}" if isinstance(key, str) and _PLAIN_KEY.fullmatch(key) else ""
                raise WatchConfigError(f"{section} has a setting this check does not know{named}.")
        self._region = _region(settings, section)
        self._tenant = _tenant(settings, section)

    def list_agents(self) -> list[ObservedAgent]:
        token = self._token()
        rows = agent_watch.Reader().records(
            _DEFINITIONS_URL.format(region=self._region), bearer=token, items="data",
            next_url=_whole_list, headers={"wd-agent-tenant-alias": self._tenant})
        found = [self._definition(row) for row in rows]
        if len({agent.external_id for agent in found}) != len(found):
            raise WatchError("Workday listed the same agent definition id more than once, which "
                             "this check cannot tell apart, so nothing from it was used.")
        return found

    def _token(self) -> str:
        """A bearer token for this run. The three values are read now, so a
        replaced secret or refresh token is picked up without a restart."""
        client, secret, refresh = (
            agent_watch.secret_named(variable, f"{key} in {self._section}")
            for key, variable in zip(_SECRET_KEYS, self._variables, strict=True))
        return _sign_in(_TOKEN_URL.format(region=self._region, tenant=self._tenant),
                        client_id=client, client_secret=secret, refresh_token=refresh)

    def _definition(self, row: dict) -> ObservedAgent:
        identifier = row.get("id")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise agent_watch.unexpected_answer()
        parts = {key: _optional(row, key, str) for key in _TEXT_FIELDS}
        capabilities = _optional(row, "capabilities", dict) or {}
        description = _optional(row, "description", str)
        provider, platform = _instance_id(row, "provider"), _instance_id(row, "platform")
        flags = {key: _optional(capabilities, key, bool) for key in _CAPABILITIES}
        extended = _optional(row, "supportsAuthenticatedExtendedCard", bool)
        hashed = {key: _digest(_optional(row, key, list)) for key in _LIST_FIELDS}
        fingerprint = agent_watch.fingerprint({
            **parts, "provider": provider, "platform": platform,
            "description": None if description is None else _sha256(description),
            "capabilities": flags, "supportsAuthenticatedExtendedCard": extended, **hashed})
        return ObservedAgent(
            platform=self.name, external_id=f"{self._tenant}/{identifier}", name=parts["name"] or "",
            version=(parts["version"] or "").strip(), fingerprint=fingerprint,
            binding_strength=OBSERVED_SNAPSHOT,
            details=self._described(row, parts, provider, platform, flags, extended, description, hashed))

    def _described(self, row: dict, parts: dict, provider: str | None, platform: str | None,
                   flags: dict, extended: bool | None, description: str | None, hashed: dict) -> dict:
        """What is kept to say later what changed: short labels, the names of
        the skills and the capabilities that are on, and digests of everything
        long. The skill, definition and description text is not kept. The
        field names are those of the agent definition in
        https://workday.github.io/asor/versions/v1.2.json (a skill's required
        ``id``, ``name`` and ``description``)."""
        skills = _optional(row, "skills", list) or []
        names = [skill.get("name") for skill in skills if isinstance(skill, dict)]
        digest = agent_watch_changes.digest
        return agent_watch_changes.describe(self.name, {
            "name": parts["name"], "version": parts["version"], "provider": provider,
            "platform_id": platform, "capabilities": [key for key, on in flags.items() if on],
            "extended_card": extended, "skills": names,
            "skill_definitions": digest(hashed["skills"]), "workday_config": digest(hashed["workdayConfig"]),
            "description": digest(None if description is None else _sha256(description)),
            "input_modes": digest(hashed["defaultInputModes"]),
            "output_modes": digest(hashed["defaultOutputModes"]),
            "url": digest(parts["url"] and _sha256(parts["url"])),
            "external_agent_id": digest(parts["externalAgentID"] and _sha256(parts["externalAgentID"])),
            "external_tenant_id": digest(parts["externalTenantID"] and _sha256(parts["externalTenantID"]))})


def _region(settings: dict, section: str) -> str:
    region = settings.get("region")
    if not isinstance(region, str) or region.strip().lower() not in _REGIONS:
        raise WatchConfigError(f"{section} needs region: one of {', '.join(_REGIONS)} (the Agent "
                               "Gateway region that hosts the tenant).")
    return region.strip().lower()


def _tenant(settings: dict, section: str) -> str:
    """The tenant alias. It is never repeated in a message, in case something
    else was typed where it belongs."""
    tenant = settings.get("tenant")
    if not isinstance(tenant, str) or not _TENANT.fullmatch(tenant.strip()):
        raise WatchConfigError(f"{section} needs tenant: the tenant alias (letters, digits, "
                               "hyphens and underscores), not an address.")
    return tenant.strip()


def _sign_in(token_url: str, *, client_id: str, client_secret: str, refresh_token: str) -> str:
    """A bearer token from Workday's refresh-token sign-in (RFC 6749 section
    6): one form POST of ``grant_type``, ``refresh_token``, ``client_id`` and
    ``client_secret`` to ``token_url``, through the framework's guarded
    request.

    Only the access token is taken from the answer, and it is handed back
    without being kept anywhere. A refusal raises :class:`WatchError` with
    the status and nothing from Workday's answer, which is not read at all."""
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token,
            "client_id": client_id, "client_secret": client_secret}
    status, body = agent_watch._request(
        "POST", token_url, headers={"Accept": "application/json"}, form=form,
        timeout=agent_watch.limits().timeout_seconds, max_bytes=_MAX_TOKEN_BYTES)
    if status != 200:
        raise WatchError(
            f"Workday refused this check's sign-in (HTTP {status}). Check the region, the tenant, "
            "the client id, the client secret and the refresh token, and that the refresh token "
            "has not expired or been replaced.")
    answer = _json_object(body)
    token, kind = answer.get("access_token"), answer.get("token_type")
    if (not isinstance(token, str) or not _TOKEN_TEXT.fullmatch(token)
            or (kind is not None and str(kind).lower() != "bearer")):
        raise WatchError("Workday's sign-in answer held no usable token, so the check did not run.")
    return token


def _json_object(body: bytes) -> dict:
    """The sign-in answer as a JSON object, or an empty one when it is not."""
    try:
        answer = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        return {}
    return answer if isinstance(answer, dict) else {}


def _whole_list(page: dict, _url: str) -> None:
    """Workday documents no paging for this list, so one answer has to be all
    of it: ``total`` must be the number of definitions sent. A count that
    does not match is an error, never a shorter list, and nothing is followed."""
    total = page.get("total")
    if isinstance(total, bool) or not isinstance(total, int):
        raise agent_watch.unexpected_answer()
    if total != len(page["data"]):
        raise WatchError(
            "Workday's count of agent definitions does not match the number it sent, so the list "
            "may be incomplete and nothing from this check was used. Workday documents no way to "
            "read this list in parts.")
    return None


def _optional(row: dict, key: str, kind: type) -> Any:
    """``row[key]`` when it is a ``kind``, ``None`` when it is absent. Any
    other value fails the run: a field that changed shape must not be
    fingerprinted as if it were empty."""
    value = row.get(key)
    if value is None:
        return None
    if not isinstance(value, kind):
        raise agent_watch.unexpected_answer()
    return value


def _instance_id(row: dict, key: str) -> str | None:
    """The ``id`` of a Workday instance reference such as ``provider``."""
    reference = _optional(row, key, dict)
    return None if reference is None else _optional(reference, "id", str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _digest(items: list | None) -> str | None:
    """A hash of a list from a definition, whatever order Workday sent its
    entries in. Nothing of the list is kept."""
    if items is None:
        return None
    try:
        return _sha256(_canonical(_unordered(items)))
    except (TypeError, ValueError, RecursionError):
        raise agent_watch.unexpected_answer() from None


def _unordered(value: Any) -> Any:
    """``value`` with every list inside it put in one fixed order. Skills,
    tags, modes and resources are sets: their order means nothing, and it
    must not change a fingerprint."""
    if isinstance(value, dict):
        return {key: _unordered(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((_unordered(item) for item in value), key=_canonical)
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


agent_watch.register(WorkdayWatcher.name, WorkdayWatcher)

__all__ = [
    "WorkdayWatcher",
]
