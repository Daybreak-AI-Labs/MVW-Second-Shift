"""Copilot Studio external threat detection: Second Shift as the service that
says allow or block before a Copilot Studio agent calls a tool.

A Power Platform administrator points an environment at this service. From then
on, every time a generative-orchestration agent in that environment is about to
call a tool, Copilot Studio asks first (``POST /validate`` to check the service
is ready, ``POST /analyze-tool-execution`` for each tool call). This module
holds the logic; the two web routes are in
``maverick_dashboard/copilot_studio_gate_api.py``. The contract:
https://learn.microsoft.com/microsoft-copilot-studio/external-security-webhooks-interface-developers
and the administrator's setup:
https://learn.microsoft.com/microsoft-copilot-studio/external-security-provider

What it does:

* Checks the caller's Microsoft Entra access token (:func:`verify_token`).
* Finds the enrolled agent the request is about. The settings map each Power
  Platform environment id to that environment's Dataverse host, so the agent's
  reference is ``copilot_studio:<host>/<agent id>``, the form the Copilot Studio
  platform check writes (``agent_watch_microsoft``): host and agent id in lower
  case, matched without regard to capital letters.
* Asks Second Shift's own screening (``external_agents.screen``) and translates
  the answer into ``blockAction``. A tool that needs a person's approval is
  blocked with the request number; once a person approves, the same agent
  asking again for the same tool with the same inputs is allowed once.

What it does not do. It never keeps the person's prompt, the chat history, the
previous tool outputs or the input values: only the environment id, the agent
id, the tool name, the decision, the reason, the time and a keyed digest of the
inputs (to bind an approval to what was asked). It never calls another service
while deciding. It does not change an agent, and it cannot make Copilot Studio
wait longer than one second: what happens when Second Shift does not answer is
Copilot Studio's own "Set error behavior".

Nothing here has been run against a real Microsoft tenant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("maverick.copilot_studio_gate")

SECTION = "copilot_studio_gate"
API_VERSION = "2025-05-01"
#: Largest request body accepted, in bytes. The prompt, recent chat and earlier
#: tool outputs travel with every call, so this is generous but bounded.
MAX_BODY_BYTES = 1024 * 1024
#: Longest Authorization header and token accepted.
_MAX_TOKEN_CHARS = 16 * 1024

# Error codes in the documented ErrorResponse body.
ERR_BAD_REQUEST = 4001
ERR_AUTH = 2003
ERR_TOO_LARGE = 4131
ERR_UNAVAILABLE = 5031

# Reason codes in a block answer. Optional in the contract; kept for tracing.
CODE_REFUSED = 101
CODE_CONTAINED = 102
CODE_EMERGENCY_STOP = 103
CODE_APPROVAL = 104
CODE_DECLINED = 105
CODE_UNENROLLED = 106
CODE_UNAVAILABLE = 107

_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_DATAVERSE_HOST = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com")
_AUDIENCE = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]{0,200})?")

_STORE_KEEP_SECONDS = 24 * 3600
_MAX_TICKETS = 1000
_MAX_SEEN = 500
_SEEN_REFRESH_SECONDS = 300
_SUMMARY_VALUES = 8
_SUMMARY_VALUE_CHARS = 80
_SUMMARY_CHARS = 400


# --------------------------------------------------------------------------
# Settings


@dataclass(frozen=True)
class GateSettings:
    """``[copilot_studio_gate]``, read once per request.

    ``problem`` is a plain sentence when the section holds a value that cannot
    be used; ``unreadable`` is set when a settings file could not be read."""

    enable: bool = False
    tenant_id: str = ""
    app_id: str = ""
    audience: str = ""
    api_client_id: str = ""
    environments: dict[str, str] = field(default_factory=dict)
    unenrolled: str = "allow"
    on_error: str = "block"
    default_risk: str = "medium"
    approval_window_seconds: float = 900.0
    record_user: bool = False
    unreadable: bool = False
    problem: str = ""

    @property
    def can_authenticate(self) -> bool:
        return bool(self.tenant_id and self.app_id and self.audience)


def load_settings() -> GateSettings:
    """Read the settings; never raises. Anything unusable is reported through
    ``problem`` or ``unreadable`` and a failure-handling value falls to the
    stricter choice (block)."""
    try:
        from .config import config_source_errors, load_config
        section = (load_config() or {}).get(SECTION, {})
        unreadable = bool(config_source_errors(include_tenant=True))
    except Exception:
        return GateSettings(unreadable=True, problem="The settings could not be read.")
    if not isinstance(section, dict):
        return GateSettings(unreadable=unreadable, problem="[copilot_studio_gate] is not a table.")
    problems: list[str] = []

    def text(key: str, pattern: re.Pattern[str], what: str) -> str:
        raw = section.get(key, "")
        if raw in ("", None):
            return ""
        if not isinstance(raw, str) or not pattern.fullmatch(raw.strip()):
            problems.append(f"{key} is not {what}.")
            return ""
        return raw.strip()

    tenant = text("tenant_id", _GUID, "a tenant id (a GUID)").lower()
    app_id = text("app_id", _GUID, "an application id (a GUID)").lower()
    api_client = text("api_client_id", _GUID, "an application id (a GUID)").lower()
    audience = text("audience", _AUDIENCE, "an https address such as https://second-shift.example.com").rstrip("/")
    environments: dict[str, str] = {}
    raw_envs = section.get("environments", {})
    if not isinstance(raw_envs, dict):
        problems.append("environments is not a table of environment id = Dataverse host.")
        raw_envs = {}
    for env_id, host in raw_envs.items():
        host_text = host.strip().lower() if isinstance(host, str) else ""
        if (not isinstance(env_id, str) or not _GUID.fullmatch(env_id.strip())
                or not _DATAVERSE_HOST.fullmatch(host_text)):
            problems.append("An entry in environments is not <environment id> = <org>.crm.dynamics.com.")
            continue
        environments[env_id.strip().lower()] = host_text
    unenrolled = str(section.get("unenrolled", "allow")).strip().lower()
    if unenrolled not in ("allow", "block"):
        problems.append("unenrolled must be \"allow\" or \"block\".")
        unenrolled = "block"
    on_error = str(section.get("on_error", "block")).strip().lower()
    if on_error not in ("allow", "block"):
        problems.append("on_error must be \"allow\" or \"block\".")
        on_error = "block"
    from .safety.tool_risk import RISK_LEVELS
    default_risk = str(section.get("default_risk", "medium")).strip().lower()
    if default_risk not in RISK_LEVELS:
        problems.append("default_risk is not a known risk level.")
        default_risk = "high"
    window = section.get("approval_window_seconds", 900)
    if isinstance(window, bool) or not isinstance(window, (int, float)) or not 60 <= window <= 3600:
        if "approval_window_seconds" in section:
            problems.append("approval_window_seconds must be between 60 and 3600.")
        window = 900
    flags = {}
    for key, default in (("enable", False), ("record_user", False)):
        value = section.get(key, default)
        if not isinstance(value, bool):
            problems.append(f"{key} must be true or false.")
            value = default if key == "record_user" else False
        flags[key] = value
    return GateSettings(
        enable=flags["enable"], tenant_id=tenant, app_id=app_id, audience=audience,
        api_client_id=api_client, environments=environments, unenrolled=unenrolled,
        on_error=on_error, default_risk=default_risk, approval_window_seconds=float(window),
        record_user=flags["record_user"], unreadable=unreadable, problem=" ".join(problems))


def ready_problem(settings: GateSettings) -> str:
    """Why Second Shift cannot make decisions now, or "" when it can."""
    from . import external_agents
    if settings.unreadable or settings.problem:
        return "Second Shift cannot read its settings for this service."
    if not settings.enable:
        return "The Copilot Studio gate is turned off in Second Shift."
    if not external_agents.enabled():
        return "Governance of outside agents is turned off in Second Shift."
    return ""


# --------------------------------------------------------------------------
# Token check


class TokenRejected(Exception):
    """The caller's token is not acceptable: answer 401."""


class TokenUnavailable(Exception):
    """The token could not be checked (signing keys unreachable): answer 503."""


def issuers(tenant_id: str) -> tuple[str, str]:
    """The two issuer forms Microsoft Entra uses for this tenant: version 2.0
    tokens and version 1.0 tokens."""
    return (f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            f"https://sts.windows.net/{tenant_id}/")


def jwks_uri(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


_TOKEN_KEY_REFUSALS = frozenset({
    "signing key is unavailable", "signing key refresh is temporarily unavailable",
    "invalid signing key identifier", "unaccepted signing algorithm"})


def verify_token(authorization: str | None, settings: GateSettings) -> dict[str, Any]:
    """Check a ``Authorization: Bearer`` access token; return its claims.

    Accepted only when all of these hold (see ``docs/copilot-studio-gate.md``
    for the Microsoft page behind each):

    * signed with RS256 by one of the tenant's published keys (never "none");
    * not expired, and not used before its start time;
    * issuer is this tenant, in the version 2.0 or version 1.0 form;
    * audience is the configured service address (``audience``), or the
      service's own application id (``api_client_id``) when one is set;
    * the ``tid`` claim is this tenant;
    * the calling application, ``azp`` in a version 2.0 token and ``appid`` in
      a version 1.0 token, is the configured ``app_id``;
    * it is an application token: a token that carries ``scp`` (a delegated,
      signed-in-user token) is refused.
    """
    from . import oidc

    if not settings.can_authenticate:
        raise TokenRejected("service is not set up to accept tokens")
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > _MAX_TOKEN_CHARS or token.count(".") != 2:
        raise TokenRejected("no bearer token")
    try:
        jwt = oidc._require_pyjwt()
    except oidc.OIDCError as exc:
        raise TokenUnavailable("token library missing") from exc
    try:
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False})
    except Exception as exc:
        raise TokenRejected("unreadable token") from exc
    if header.get("alg") != "RS256" or not isinstance(unverified, dict):
        raise TokenRejected("signature algorithm not accepted")
    issuer = unverified.get("iss")
    if issuer not in issuers(settings.tenant_id):
        raise TokenRejected("issuer not accepted")
    accepted = [settings.audience] + ([settings.api_client_id] if settings.api_client_id else [])
    audience = unverified.get("aud")
    if not isinstance(audience, str) or audience.lower() not in [a.lower() for a in accepted]:
        raise TokenRejected("audience not accepted")
    audience = next(a for a in accepted if a.lower() == audience.lower())
    config = oidc.OIDCConfig(enabled=True, issuer=issuer, audience=audience,
                             jwks_uri=jwks_uri(settings.tenant_id), algorithms=["RS256"])
    try:
        from ._oidc_jwks import ResolverError, resolve
        key = resolve(jwt, token, config)
    except ResolverError as exc:
        # The tenant's keys were read and none matches this token (or a refresh
        # for an unknown key is cooling down): a bad token. Capacity is ours.
        if str(exc) in _TOKEN_KEY_REFUSALS:
            raise TokenRejected("signing key not accepted") from exc
        raise TokenUnavailable("signing keys unavailable") from exc
    except Exception as exc:
        raise TokenUnavailable("signing keys unavailable") from exc
    try:
        claims = oidc.verify_oidc_token(token, config=config, signing_key=key).claims
    except oidc.OIDCError as exc:
        raise TokenRejected("token failed verification") from exc
    if str(claims.get("tid", "")).lower() != settings.tenant_id or "scp" in claims:
        raise TokenRejected("token is not an application token of this tenant")
    caller = claims.get("azp") if issuer == issuers(settings.tenant_id)[0] else claims.get("appid")
    if not isinstance(caller, str) or caller.lower() != settings.app_id:
        raise TokenRejected("calling application not accepted")
    return claims


# --------------------------------------------------------------------------
# Request


class BadRequest(Exception):
    def __init__(self, message: str, status: int = 400, code: int = ERR_BAD_REQUEST):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


@dataclass(frozen=True)
class ToolRequest:
    """The few facts of a request that are used. The prompt, chat history and
    tool outputs are never copied out of the request body."""

    environment_id: str
    agent_id: str
    tool: str
    inputs: dict[str, Any]
    user_id: str = ""


def _printable(value: str, limit: int) -> str:
    return " ".join("".join(c for c in value if c.isprintable() or c.isspace()).split())[:limit]


def parse_request(body: bytes) -> ToolRequest:
    """Read an ``analyze-tool-execution`` body. Unknown fields are ignored."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise BadRequest("The request body is not valid JSON.") from None
    if not isinstance(data, dict):
        raise BadRequest("The request body must be a JSON object.")

    def child(parent: Any, key: str) -> Any:
        return parent.get(key) if isinstance(parent, dict) else None

    tool = child(child(data, "toolDefinition"), "name")
    if not isinstance(child(data, "toolDefinition"), dict):
        raise BadRequest("Missing required field: toolDefinition")
    meta = child(data, "conversationMetadata")
    agent = child(meta, "agent")
    if not isinstance(agent, dict):
        raise BadRequest("Missing required field: conversationMetadata.agent")
    tool = _printable(tool, 200) if isinstance(tool, str) else ""
    agent_id, env_id = agent.get("id"), agent.get("environmentId")
    if not tool:
        raise BadRequest("Missing required field: toolDefinition.name")
    if not isinstance(agent_id, str) or not 1 <= len(agent_id.strip()) <= 100:
        raise BadRequest("Missing required field: conversationMetadata.agent.id")
    if not isinstance(env_id, str) or not 1 <= len(env_id.strip()) <= 100:
        raise BadRequest("Missing required field: conversationMetadata.agent.environmentId")
    inputs = data.get("inputValues", {})
    if inputs is None:
        inputs = {}
    if not isinstance(inputs, dict):
        raise BadRequest("inputValues must be a JSON object.")
    user = child(child(meta, "user"), "id")
    return ToolRequest(
        environment_id=env_id.strip().lower(), agent_id=agent_id.strip().lower(), tool=tool,
        inputs=inputs, user_id=_printable(user, 100) if isinstance(user, str) else "")


def _summary(inputs: dict[str, Any]) -> str:
    """A short, redacted look at the proposed input values, for the person
    deciding. "" when it cannot be made safely."""
    from .safety.secret_detector import redact
    parts = []
    for key in sorted(inputs, key=str)[:_SUMMARY_VALUES]:
        value = inputs[key]
        if not isinstance(value, str):
            try:
                value = json.dumps(value, sort_keys=True, default=str)
            except (TypeError, ValueError):
                value = "(not shown)"
        parts.append(f"{_printable(str(key), 40)}: {_printable(redact(value)[0], _SUMMARY_VALUE_CHARS)}")
    return "; ".join(parts)[:_SUMMARY_CHARS]


def _show_detail() -> bool:
    try:
        from .config import get_external_agents
        return bool(get_external_agents()["show_request_detail"])
    except Exception:
        return False


# --------------------------------------------------------------------------
# Decision


@dataclass(frozen=True)
class Verdict:
    block: bool
    rule: str
    reason: str = ""
    code: int = 0
    #: True when Second Shift's screening already wrote the audit entry.
    screened: bool = False

    def body(self) -> dict[str, Any]:
        if not self.block:
            return {"blockAction": False}
        return {"blockAction": True, "reasonCode": self.code, "reason": self.reason}


def _blocked(rule: str, why: str, code: int, *, screened: bool = False) -> Verdict:
    return Verdict(True, rule, f"Second Shift blocked this action: {why}", code, screened)


def _unavailable(settings: GateSettings, rule: str) -> Verdict:
    """Second Shift cannot decide: answer as the administrator chose."""
    if settings.on_error == "allow":
        return Verdict(False, rule)
    return _blocked(rule, "it could not check this request just now. Try again shortly.", CODE_UNAVAILABLE)


_lock = threading.RLock()


def store_path():
    from .paths import data_dir
    return data_dir("copilot_studio_gate.json")


@contextmanager
def _store():
    """The gate's small record, locked, read, and written back on exit. It is
    kept with the other records (``maverick.record_documents``). It holds approval tickets and the agents seen but not enrolled, nothing
    from a conversation."""
    from .record_documents import at
    record = at(store_path())
    with _lock, record.locked():
        try:
            text = record.read_text()
            data = json.loads(text) if text is not None else {}
            if not isinstance(data, dict):
                raise ValueError("not an object")
        except (OSError, ValueError):
            raise RuntimeError("the gate's records cannot be read") from None
        data.setdefault("salt", secrets.token_hex(16))
        data.setdefault("tickets", {})
        data.setdefault("seen", {})
        before = json.dumps(data, sort_keys=True)
        yield data
        now = time.time()
        data["tickets"] = {k: v for k, v in sorted(
            data["tickets"].items(), key=lambda kv: kv[1].get("created", 0), reverse=True
        )[:_MAX_TICKETS] if now - float(v.get("created", 0)) < _STORE_KEEP_SECONDS}
        data["seen"] = dict(sorted(
            data["seen"].items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)[:_MAX_SEEN])
        if json.dumps(data, sort_keys=True) != before:
            record.write_text(json.dumps(data, indent=2, sort_keys=True))


def _digest(salt: str, req: ToolRequest) -> str:
    """Keyed digest of agent, tool and inputs. Only this is kept, so the inputs
    themselves cannot be read back from the record."""
    material = json.dumps(
        {"env": req.environment_id, "agent": req.agent_id, "tool": req.tool, "inputs": req.inputs},
        sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)
    return hmac.new(salt.encode(), material.encode(), hashlib.sha256).hexdigest()


def agent_reference(host: str, agent_id: str) -> str:
    """The reference an enrolled Copilot Studio agent carries: the same form
    the Copilot Studio platform check writes."""
    return f"copilot_studio:{host}/{agent_id}".lower()


def _find_enrolled(reference: str) -> tuple[str, dict] | None:
    from . import external_agents as xa
    for agent_id, meta in xa._load_sidecar(strict=True).items():
        if str(meta.get("external_ref") or "").casefold() == reference:
            return agent_id, meta
    return None


def _audit(req: ToolRequest, settings: GateSettings, verdict: Verdict, reference: str) -> None:
    from .audit import EventKind, audit_event
    extra = {"user_id": req.user_id} if settings.record_user and req.user_id else {}
    audit_event(EventKind.EXTERNAL_ACTION_SCREENED, agent="copilot_studio_gate",
                environment_id=req.environment_id, external_agent=reference, tool=req.tool,
                allowed=not verdict.block, rule=verdict.rule, reason=verdict.reason, **extra)


def _note_unenrolled(req: ToolRequest, reference: str, now: float) -> None:
    with _store() as data:
        row = data["seen"].get(reference)
        if row is not None and now - float(row.get("last_seen", 0)) < _SEEN_REFRESH_SECONDS:
            return
        data["seen"][reference] = {
            "environment_id": req.environment_id, "agent_id": req.agent_id,
            "reference": reference, "tool": req.tool,
            "first_seen": (row or {}).get("first_seen", now), "last_seen": now}


def seen_unenrolled() -> list[dict]:
    """Agents that asked about a tool while not enrolled, newest first."""
    with _store() as data:
        rows = [dict(v) for v in data["seen"].values()]
    return sorted(rows, key=lambda r: r.get("last_seen", 0), reverse=True)


def decide(req: ToolRequest, settings: GateSettings, *, now: float | None = None) -> Verdict:
    """The answer to one ``analyze-tool-execution`` request. Never raises:
    anything unexpected is answered by ``on_error``."""
    now = time.time() if now is None else now
    try:
        verdict, reference = _decide(req, settings, now)
    except Exception as exc:
        from .audit import AuditRefused
        if isinstance(exc, AuditRefused):  # the audit log may not be skipped
            return _blocked("audit_refused", "it could not record this decision.", CODE_UNAVAILABLE)
        # Type only: a message could quote what was asked.
        log.warning("copilot_studio_gate: could not decide (%s)", type(exc).__name__)
        verdict, reference = _unavailable(settings, "error"), ""
    if not verdict.screened:
        try:
            _audit(req, settings, verdict, reference)
        except Exception as exc:
            from .audit import AuditRefused
            if isinstance(exc, AuditRefused):
                return _blocked("audit_refused", "it could not record this decision.", CODE_UNAVAILABLE)
            log.warning("copilot_studio_gate: audit failed (%s)", type(exc).__name__)
    return verdict


def _decide(req: ToolRequest, settings: GateSettings, now: float) -> tuple[Verdict, str]:
    from . import external_agents as xa

    if ready_problem(settings):
        return _unavailable(settings, "gate_off"), ""
    host = settings.environments.get(req.environment_id)
    reference = agent_reference(host, req.agent_id) if host else ""
    found = _find_enrolled(reference) if reference else None
    if found is None:
        if host:
            _note_unenrolled(req, reference, now)
        rule = "unenrolled" if host else "unknown_environment"
        if settings.unenrolled == "block":
            return _blocked(
                "unenrolled_blocked", "this agent is not enrolled in Second Shift yet. "
                "Ask an administrator to enroll it.", CODE_UNENROLLED), reference
        return Verdict(False, rule), reference
    agent_id, meta = found
    risk = (meta.get("tool_risks") or {}).get(req.tool) or settings.default_risk
    detail = _summary(req.inputs) if _show_detail() else ""

    retry = _approved_retry(req, settings, agent_id, now, risk, detail)
    if retry is not None:
        return retry, reference
    with _store() as data:
        ticket = data["tickets"].get(_digest(data["salt"], req))
    if ticket and not ticket.get("used") and now - float(ticket.get("created", 0)) < settings.approval_window_seconds:
        waiting = _ticket_state(agent_id, ticket)
        if waiting == "pending":
            return _needs_approval("approval_pending", ticket["approval_id"]), reference
        if waiting == "denied":
            return _blocked(
                "approval_declined", f"a person declined this action in Second Shift "
                f"(request #{ticket['approval_id']}).", CODE_DECLINED), reference

    screened = xa.screen(agent_id, req.tool, detail=detail, risk=risk)
    if screened.get("allowed"):
        return Verdict(False, str(screened.get("rule") or "allow"), screened=True), reference
    if screened.get("requires_approval"):
        approval_id = int(screened["approval_id"])
        with _store() as data:
            data["tickets"][_digest(data["salt"], req)] = {
                "agent_id": agent_id, "approval_id": approval_id, "created": now, "used": False}
        return _needs_approval(str(screened.get("rule") or "approval_required"), approval_id,
                               screened=True), reference
    return _refusal(screened), reference


def _refusal(screened: dict) -> Verdict:
    """A refusal from screening, in words the person in the chat will read."""
    rule = str(screened.get("rule") or "refused")
    if rule == "contained":
        return _blocked(rule, "this agent is paused while an administrator reviews it.",
                        CODE_CONTAINED, screened=True)
    if rule == "halted":
        return _blocked(rule, "the emergency stop is on.", CODE_EMERGENCY_STOP, screened=True)
    why = str(screened.get("reason") or "it is not permitted.").strip().rstrip(".")[:300]
    return _blocked(rule, why + ".", CODE_REFUSED, screened=True)


def _needs_approval(rule: str, approval_id: Any, *, screened: bool = False) -> Verdict:
    return Verdict(True, rule, f"This action needs approval in Second Shift (request #{approval_id}). "
                   "Ask again once it has been approved.", CODE_APPROVAL, screened)


def _ticket_state(agent_id: str, ticket: dict) -> str:
    """"approved", "denied", "pending", or "unknown" for a ticket's approval."""
    from . import external_agents as xa
    try:
        return str(xa.approval_status(agent_id, int(ticket["approval_id"]))["status"])
    except xa.ExternalAgentsError:
        return "unknown"


def _approved_retry(req: ToolRequest, settings: GateSettings, agent_id: str, now: float,
                    risk: str, detail: str) -> Verdict | None:
    """Allow once an action a person approved, when the same agent asks again
    for the same tool with the same inputs. ``None`` when there is no such
    approval. Everything except the approval floor is checked again first, so
    an emergency stop, containment or a withdrawn enrollment still refuses."""
    from . import external_agents as xa
    from .world_model import open_world

    with _store() as data:
        key = _digest(data["salt"], req)
        ticket = data["tickets"].get(key)
        if not ticket or ticket.get("used") or ticket.get("agent_id") != agent_id:
            return None
        if _ticket_state(agent_id, ticket) != "approved":
            return None
        approval = open_world().get_approval(int(ticket["approval_id"]))
        decided = float(getattr(approval, "decided_at", None) or ticket.get("created", 0))
        if now - decided > settings.approval_window_seconds:
            return None
        if xa._emergency_stop_on():
            return _blocked("halted", "the emergency stop is on.", CODE_EMERGENCY_STOP)
        deny, _meta, _decision, _risk = xa._screen_admission(
            agent_id, req.tool, risk=risk, detail=detail, shield=None)
        if deny is not None:
            return _refusal(deny)
        ticket["used"] = True  # a used approval cannot be reused
        ticket["used_at"] = now
    return Verdict(False, "approved_once")
