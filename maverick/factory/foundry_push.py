"""Push a released factory agent to Microsoft Foundry: create the prompt agent in one configured project.

Off unless ``[factory.foundry] allow_push = true``. Second Shift signs in with its own credentials (an app registration
by client credentials, or a managed identity), never the credentials of the person who clicked. Settings hold the NAMES of
environment variables, never a secret.

Rules, as for every write to another platform: administrators only; the request must name the project and the agent it
was shown; it is audited before it is sent and again with its outcome (ids, names and status, never the definition or a
credential); it is sent once and never retried; if the audit log cannot take the request, nothing is sent. On success the
agent's enrollment is linked to the Foundry agent (``foundry:<resource>/<project>/<agent name>``, the form the platform
check reads), so a change made later in Foundry shows up as drift.

Requests (https://learn.microsoft.com/azure/foundry/agents/quickstarts/prompt-agent):

* ``POST {project endpoint}/agents?api-version=v1`` with ``{"name", "description", "definition": {"kind": "prompt", ...}}``
  creates the agent. The token is for ``https://ai.azure.com/.default``
  (https://learn.microsoft.com/azure/foundry/concepts/authentication-authorization-foundry).
* ``POST {project endpoint}/agents/{name}/versions?api-version=v1`` with ``{"description", "definition"}`` adds a version to an
  agent that exists. Microsoft's page for Foundry Local shows this route
  (https://learn.microsoft.com/azure/azure-arc/agents-tools-foundry-local/create-manage-agents); it was not confirmed on the
  cloud Foundry page.
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from typing import Any

from . import FactoryError, store
from .export import check_skills_url, foundry_agent_body, foundry_agent_name

log = logging.getLogger("maverick.factory.foundry_push")

SCOPE = "https://ai.azure.com/.default"
MODES = ("create", "new_version")
_ENDPOINT = re.compile(r"https://([A-Za-z0-9][A-Za-z0-9-]{0,62})\.services\.ai\.azure\.com/api/projects/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/?",
                       re.IGNORECASE)
_CONNECTION = re.compile(r"/subscriptions/[^/\s]{1,100}/resourceGroups/[^/\s]{1,100}/providers/Microsoft\.CognitiveServices/"
                         r"accounts/[^/\s]{1,100}/projects/[^/\s]{1,100}/connections/[^/\s]{1,100}", re.IGNORECASE)
_KNOWN = {"allow_push", "project_endpoint", "auth", "tenant_id_env", "client_id_env", "client_secret_env"}
_busy = threading.Lock()

NOT_ALLOWED = ("Pushing to Microsoft Foundry is turned off. An administrator can turn it on with allow_push = true in the "
               "[factory.foundry] settings, after naming the project and the sign-in to use. You can still download the package and "
               "create the agent yourself.")


@dataclass(frozen=True)
class FoundrySettings:
    allow_push: bool
    project: str  # "<resource>/<project>", "" when not set
    endpoint: str
    auth: str
    tenant_env: str
    client_env: str
    secret_env: str
    problems: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return self.allow_push and not self.problems


def settings() -> FoundrySettings:
    """The ``[factory.foundry]`` settings, checked. Anything that cannot be used is listed in ``problems`` in plain words
    (a value is never repeated, in case a secret was typed where a name belongs)."""
    try:
        from ..config import load_config

        factory = (load_config() or {}).get("factory")
        table = factory.get("foundry") if isinstance(factory, dict) else None
    except Exception:
        return FoundrySettings(False, "", "", "", "", "", "", ("The settings could not be read.",))
    table = table if isinstance(table, dict) else {}
    problems: list[str] = []
    allow = table.get("allow_push", False)
    if not isinstance(allow, bool):
        problems.append("allow_push in [factory.foundry] must be true or false.")
        allow = False
    for key in table:
        if key not in _KNOWN:
            problems.append("[factory.foundry] has a setting this version does not know" +
                            (f": {key}" if re.fullmatch(r"[A-Za-z0-9_]{1,40}", str(key)) else "") + ".")
    endpoint, project = "", ""
    raw = table.get("project_endpoint")
    match = _ENDPOINT.fullmatch(raw.strip()) if isinstance(raw, str) else None
    if match is None:
        problems.append("project_endpoint in [factory.foundry] must be the project's address, "
                        "https://<resource>.services.ai.azure.com/api/projects/<project>.")
    else:
        project = f"{match.group(1).lower()}/{match.group(2)}"
        endpoint = f"https://{match.group(1).lower()}.services.ai.azure.com/api/projects/{match.group(2)}"
    auth = table.get("auth", "client_credentials")
    if auth not in ("client_credentials", "managed_identity"):
        problems.append("auth in [factory.foundry] must be client_credentials or managed_identity.")
        auth = ""
    names: dict[str, str] = {}
    required = {"tenant_id_env", "client_id_env", "client_secret_env"} if auth == "client_credentials" else set()
    for key in ("tenant_id_env", "client_id_env", "client_secret_env"):
        value = table.get(key)
        names[key] = ""
        if value is None:
            if key in required:
                problems.append(f"{key} in [factory.foundry] is needed: the name of an environment variable.")
        elif isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
            names[key] = value
        else:
            problems.append(f"{key} in [factory.foundry] must be the name of an environment variable, not the value itself.")
    if "client_secret" in table:
        problems.append("[factory.foundry] must not hold the client secret itself. Put it in an environment variable and name it in client_secret_env.")
    return FoundrySettings(allow, project, endpoint, auth, names["tenant_id_env"], names["client_id_env"], names["client_secret_env"], tuple(problems))


def status() -> dict[str, Any]:
    """What the page shows: whether push is on and set up, and where it would go. No credential, no address of a secret."""
    s = settings()
    return {"allowed": s.allow_push, "ready": s.ready, "project": s.project, "problems": list(s.problems)}


def external_ref(project: str, name: str) -> str:
    """The platform link the Foundry check reads: ``foundry:<resource>/<project>/<agent name>``."""
    return f"foundry:{project}/{name}"


def _token(s: FoundrySettings) -> str:
    """A token for Foundry from Second Shift's own credentials. Raises FactoryError, in plain words, when none can be had."""
    from .. import agent_watch
    from ..agent_watch_microsoft import _Credentials

    try:
        if s.auth == "client_credentials":
            return _Credentials("[factory.foundry]", s.tenant_env, s.client_env, s.secret_env).token(SCOPE)
        try:
            from azure.identity import ManagedIdentityCredential  # type: ignore
        except ImportError as exc:
            raise FactoryError("Signing in with a managed identity needs the azure-identity package "
                               "(pip install azure-identity). Nothing was sent.", 409) from exc
        import os

        client_id = os.environ.get(s.client_env, "").strip() if s.client_env else ""
        return ManagedIdentityCredential(client_id=client_id or None).get_token(SCOPE).token
    except FactoryError:
        raise
    except agent_watch.WatchError as exc:
        raise FactoryError(f"Second Shift could not sign in to Microsoft. {agent_watch._safe_message(exc)} Nothing was sent.", 409) from exc
    except Exception as exc:
        log.warning("foundry sign-in failed (%s)", type(exc).__name__)
        raise FactoryError("Second Shift could not sign in to Microsoft. Check the sign-in settings. Nothing was sent.", 409) from exc


def _refusal(status_code: int) -> str:
    if status_code == 401:
        return "Foundry did not accept Second Shift's sign-in (HTTP 401). Check the client id and secret, and that the secret has not expired."
    if status_code == 403:
        return ("Foundry refused (HTTP 403). The sign-in probably does not have permission to create agents in this project; "
                "see Microsoft's Foundry role-based access control page for the role it needs.")
    if status_code == 404:
        return "Foundry has nothing at that address (HTTP 404). Check project_endpoint, and the agent name when adding a version."
    if status_code == 409:
        return ("Foundry says an agent with this name already exists (HTTP 409). Second Shift does not overwrite it. "
                "Choose \"Add a version to the existing agent\" to add this version to it.")
    if status_code in (400, 422):
        return (f"Foundry did not accept the agent's definition (HTTP {status_code}). Check that the model deployment exists in the "
                "project and that the project connection id is right.")
    if status_code == 429:
        return "Foundry is limiting requests at the moment (HTTP 429). Try again in a few minutes."
    return f"Foundry answered with HTTP {status_code}, which Second Shift did not expect."


def _audit(kind: str, record: dict[str, Any], number: int, who: str, project: str, name: str, **payload: Any) -> bool:
    from maverick.audit import audit_event

    return bool(audit_event(kind, agent="factory", factory_agent=record["id"], external_agent=record["agent_id"], version=number,
                            platform="foundry", project=project, foundry_agent=name, requested_by=who, **payload))


def push(fac_id: str, number: int, who: str, *, confirm_project: str, confirm_agent: str, skills_url: str, connection_id: str,
         mode: str = "create") -> dict[str, Any]:
    """Create the prompt agent (or add a version to it) in the configured Foundry project. The caller must already have
    checked that the person is an administrator. Returns what was done; raises FactoryError, in plain words, when it was
    refused or failed. Never retries."""

    s = settings()
    if not s.allow_push:
        raise FactoryError(NOT_ALLOWED, 409)
    if s.problems:
        raise FactoryError("Push to Foundry is on but not set up: " + " ".join(s.problems), 409)
    if mode not in MODES:
        raise FactoryError("The mode must be create or new_version.", 422)
    record = store.get(fac_id)
    version = store.find_version(record, number)
    if version["state"] != "released":
        raise FactoryError("Only the released version can be pushed.", 409)
    enrollment = record.get("enrollment") or {}
    if enrollment.get("status") != "enrolled" or enrollment.get("enrolled_version") != number:
        raise FactoryError("Only the released version's agent is enrolled in Second Shift, so only it can be pushed.", 409)
    name = foundry_agent_name(record)
    if confirm_project.strip().casefold() != s.project.casefold() or confirm_agent.strip() != name:
        raise FactoryError("The confirmation does not match the project and agent this would create. Nothing was sent.", 409)
    skills_url = check_skills_url(skills_url)
    if not skills_url:
        raise FactoryError("Give the address of the skills service. The agent's tools are that service.", 422)
    if not _CONNECTION.fullmatch(connection_id.strip()):
        raise FactoryError("The project connection must be its full resource id, /subscriptions/.../connections/<name>.", 422)
    body = foundry_agent_body(record, version, skills_url, connection_id.strip())
    from ..control_plane_lease import try_dashboard_operation

    with try_dashboard_operation(_busy, 'foundry-push') as acquired:
        if not acquired:
            raise FactoryError("A push is already being sent. Wait for it to finish.", 409)
        return _send(record, number, who, s, name, body, mode)


def _send(record: dict[str, Any], number: int, who: str, s: FoundrySettings, name: str, body: dict[str, Any], mode: str) -> dict[str, Any]:
    from .. import agent_watch

    if not _audit("factory_foundry_push_requested", record, number, who, s.project, name, mode=mode):
        raise FactoryError("The audit log could not take a record of this request, so nothing was sent.", 503)
    try:
        token = _token(s)
        if mode == "create":
            url, payload = f"{s.endpoint}/agents?api-version=v1", body
        else:
            url, payload = f"{s.endpoint}/agents/{name}/versions?api-version=v1", {"description": body["description"], "definition": body["definition"]}
        code, answer = agent_watch._request(
            "POST", url, headers={"Accept": "application/json", "Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=agent_watch.limits().timeout_seconds, max_bytes=1_000_000, json_body=payload, ok=(200, 201), error_body=True)
    except FactoryError as exc:
        _audit("factory_foundry_push_failed", record, number, who, s.project, name, mode=mode, outcome="not_sent")
        raise exc
    except agent_watch.WatchError as exc:
        _audit("factory_foundry_push_failed", record, number, who, s.project, name, mode=mode, outcome="failed")
        raise FactoryError(f"{agent_watch._safe_message(exc)} Nothing was changed in Second Shift. The request was not repeated.", 502) from None
    except Exception as exc:
        log.warning("foundry push stopped unexpectedly (%s)", type(exc).__name__)
        _audit("factory_foundry_push_failed", record, number, who, s.project, name, mode=mode, outcome="failed")
        raise FactoryError("The push stopped because of an unexpected problem. The server log has the details. The request was not repeated.", 502) from None
    if code not in (200, 201):
        _audit("factory_foundry_push_failed", record, number, who, s.project, name, mode=mode, outcome="refused", http_status=code)
        raise FactoryError(f"{_refusal(code)} Nothing was changed in Second Shift. The request was not repeated.", 502)
    _audit("factory_foundry_push_made", record, number, who, s.project, name, mode=mode, outcome="created", http_status=code)
    linked, note = _link(record, number, who, s.project, name)
    return {"ok": True, "project": s.project, "agent": name, "mode": mode, "external_ref": external_ref(s.project, name) if linked else None,
            "linked": linked, "message": (f"The agent {name} was {'created' if mode == 'create' else 'given a new version'} in {s.project}. " + note).strip()}


def _link(record: dict[str, Any], number: int, who: str, project: str, name: str) -> tuple[bool, str]:
    """Set the enrollment's external_ref so the platform check ties Foundry changes to this agent."""
    from maverick import external_agents

    from . import release

    ref = external_ref(project, name)
    try:
        fresh = store.get(record["id"])
        version = store.find_version(fresh, number)
        approvers = list((version.get("approval") or {}).get("approved_by") or []) or [who]
        release._enroll(fresh, version, approvers, external_ref=ref)

        def apply(rec: dict[str, Any]) -> None:
            if rec.get("enrollment"):
                rec["enrollment"]["external_ref"] = ref
            rec["foundry"] = {"project": project, "agent": name, "pushed_version": number, "pushed_by": who, "pushed_at": store.now(), "external_ref": ref}
            store.log(store.find_version(rec, number), who, f"Pushed to Microsoft Foundry as {name} in {project}.")

        store.change(record["id"], who, "foundry_pushed", apply)
    except (FactoryError, external_agents.ExternalAgentsError) as exc:
        log.warning("foundry push could not link the enrollment")
        from maverick.audit import audit_event

        audit_event("factory_foundry_link_failed", agent="factory", factory_agent=record["id"], external_agent=record["agent_id"], reason=str(exc)[:200])
        return False, (f"It could not be linked to this agent in Second Shift ({exc}). Set the platform link {ref} on the Outside agents page by hand.")
    return True, "Second Shift now ties changes made to it in Foundry to this agent."
