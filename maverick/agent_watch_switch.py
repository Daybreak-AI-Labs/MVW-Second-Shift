"""Switch an outside agent off on its own platform, where the platform allows it.

Blocking an agent in Second Shift only makes Second Shift refuse its calls.
For a platform whose vendor documents a way to disable an agent, an
administrator can also switch it off there:

* ``offer`` -- what can be done for one agent, in plain words: whether its
  platform has a documented way, whether this installation allows it, and
  what the person does instead when it cannot.
* ``switch`` -- one guarded write: disable (``"off"``) or re-enable (``"on"``).

Only Microsoft Entra Agent ID has one: Microsoft documents disabling an agent
identity through Microsoft Graph with the application permission
``AgentIdentity.EnableDisable.All``. Copilot Studio can quarantine an agent
only for a signed-in administrator, not an app; Workday has no API for it;
ServiceNow documents deactivation only in AI Agent Studio; Foundry is not
built here. For those the offer says so and what the administrator does.

Rules. Off unless the platform's settings section says
``allow_switch_off = true``. The caller names an enrolled agent and nothing
else: the platform id comes from the agent's ``external_ref`` and is checked
again before it goes into an address. The request is audited before it is
sent and again with its outcome (agent id, platform, action, who asked and
the result; nothing the platform said). It is sent once and never retried. A
failure is explained in plain words and changes nothing in Second Shift's own
records. Credentials are read by environment-variable name through the
platform check's own sign-in and never appear in a message, a log or the
audit trail. If the audit log cannot take the request, nothing is sent.
"""
from __future__ import annotations

import logging
import threading

from . import agent_watch
from .agent_watch import AgentWatchError, WatchConfigError, WatchError

log = logging.getLogger("maverick.agent_watch_switch")

ACTIONS = ("off", "on")

_NOT_LINKED = ("This agent is not linked to a platform record, so Second Shift cannot switch it off "
               "there. Switch it off where it runs, or use Pause here so Second Shift refuses its calls.")
#: What the person does when Second Shift cannot do it for them, by platform.
_CANNOT = {
    "copilot_studio": (
        "Second Shift cannot switch off a Copilot Studio agent. Microsoft lets only a signed-in "
        "administrator quarantine one (a Global, AI or Power Platform administrator), not an app. "
        "Ask one of them to quarantine it, or use Pause here so Second Shift refuses its calls."),
    "workday": (
        "Second Shift cannot switch off a Workday agent: Workday offers no way to do it from "
        "outside. An administrator switches it off in Workday's Agent Management Hub. Until then, "
        "use Pause here so Second Shift refuses its calls."),
    "servicenow": (
        "Second Shift cannot switch off a ServiceNow agent: ServiceNow documents deactivating one "
        "only in AI Agent Studio (the Deactivate button, which needs the sn_aia.admin role), not "
        "through its API. An administrator does it there, or use Pause here so Second Shift "
        "refuses its calls."),
    "foundry": (
        "Second Shift does not switch Microsoft Foundry agents off yet. An administrator disables "
        "the agent in the Foundry portal, or use Pause here so Second Shift refuses its calls."),
}
_CANNOT_OTHER = ("Second Shift cannot switch agents off on this platform. Switch it off where it runs, "
                 "or use Pause here so Second Shift refuses its calls.")
_NOT_ALLOWED = ("Switching this agent off from Second Shift is turned off. An administrator can allow "
                "it with allow_switch_off = true in the [agent_watch.{platform}] settings, after "
                "granting the check's app registration the Microsoft Graph application permission "
                "AgentIdentity.EnableDisable.All (see docs/platform-checks.md).")
_AUDIT_DOWN = ("The audit log could not take a record of this request, so nothing was sent to the "
               "platform and nothing was changed.")
_BUSY = "A change for this agent is already being sent. Wait for it to finish."
_NOT_DONE = " Nothing was changed on the platform or in Second Shift."

_busy = threading.Lock()


class SwitchRefused(AgentWatchError):
    """The request was refused before anything was sent. ``status`` is the HTTP
    answer an interface gives (404 not enrolled, 409 it cannot be done, 503 the
    record or audit log cannot be used); the message is plain language."""

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


class SwitchFailed(AgentWatchError):
    """The platform did not take the change. The message is plain language and
    holds nothing the platform said beyond its status."""

    def __init__(self, message: str, http_status: int | None = None) -> None:
        super().__init__(message)
        self.http_status = http_status


def _link(agent_id: str) -> tuple[str, str] | None:
    """The (platform, platform id) an enrolled agent is linked to, ``None``
    when it is enrolled with no usable link. Raises :class:`SwitchRefused`
    (404) for an agent that is not enrolled, and
    :class:`~maverick.agent_watch.AgentWatchStoreError` for a record that
    cannot be read."""
    from . import external_agents
    try:
        enrolled = external_agents._load_sidecar(strict=True)
    except external_agents.ExternalAgentsDependencyError as e:
        raise agent_watch.AgentWatchStoreError(
            "The enrollment record cannot be read, so nothing was changed.") from e
    if agent_id not in enrolled:
        raise SwitchRefused("This agent is not enrolled.", 404)
    parsed = agent_watch._parse_ref(enrolled[agent_id].get("external_ref"))
    return None if parsed is None else parsed


def _watcher(platform: str):
    """The platform's check built from its settings, ``None`` when there is no
    check of that name, or the message when its settings cannot be used."""
    try:
        return agent_watch._build(platform), ""
    except WatchConfigError as e:
        return None, agent_watch._safe_message(e)


def offer(agent_id: str) -> dict:
    """What can be done to switch ``agent_id`` off on its platform:
    ``{"linked", "platform", "platform_name", "supported", "allowed", "state",
    "reason"}``. ``supported`` is whether the platform has a documented way,
    ``allowed`` whether this installation's settings turn it on, ``state`` what
    the last platform check saw ("enabled", "disabled" or ""), and ``reason``
    says in plain words why it cannot be done (empty when it can). Reads
    only; raises :class:`SwitchRefused` (404) for an agent that is not
    enrolled."""
    from .agent_watch_changes import PLATFORM_NAMES
    link = _link(agent_id)
    if link is None:
        return {"linked": False, "platform": "", "platform_name": "", "supported": False,
                "allowed": False, "state": "", "reason": _NOT_LINKED}
    platform = link[0]
    out = {"linked": True, "platform": platform,
           "platform_name": PLATFORM_NAMES.get(platform, platform), "supported": False,
           "allowed": False, "state": "", "reason": ""}
    agent_watch._load_watchers()
    if not hasattr(agent_watch._FACTORIES.get(platform), "switch"):
        out["reason"] = _CANNOT.get(platform, _CANNOT_OTHER)
        return out
    out["supported"] = True
    watcher, problem = _watcher(platform)
    if watcher is None:
        out["reason"] = problem  # settings that cannot be used: never read as "allowed"
        return out
    view = agent_watch.platform_view(agent_id) or {}
    out["state"] = view.get("state", "") if view.get("listed") is not False else ""
    out["allowed"] = bool(watcher.allow_switch_off)
    if not out["allowed"]:
        out["reason"] = _NOT_ALLOWED.format(platform=platform)
    return out


def switch(agent_id: str, *, action: str, actor: str) -> dict:
    """Disable (``action="off"``) or re-enable (``"on"``) ``agent_id`` on its
    platform. The caller must already have checked that the person may and
    has confirmed. Returns ``{"ok": True, "platform", "platform_name",
    "action", "message"}``.

    Raises :class:`SwitchRefused` before anything is sent (not enrolled, no
    link, no documented way on the platform, not allowed in the settings, a
    platform id that is not an identity id, an audit log that cannot take the
    request) and :class:`SwitchFailed` when the platform did not take it."""
    if action not in ACTIONS:
        raise SwitchRefused("The action must be off or on.", 422)
    what = offer(agent_id)
    if not what["linked"] or not what["supported"] or not what["allowed"]:
        raise SwitchRefused(what["reason"] or _CANNOT_OTHER)
    platform = what["platform"]
    link = _link(agent_id)
    watcher, problem = _watcher(platform)
    if link is None or watcher is None:
        raise SwitchRefused(problem or _NOT_LINKED)
    from .control_plane_lease import try_dashboard_operation

    with try_dashboard_operation(_busy, 'platform-switch') as acquired:
        if not acquired:
            raise SwitchRefused(_BUSY)
        return _send(agent_id, platform, what["platform_name"], link[1], watcher, action, actor)


def _send(agent_id: str, platform: str, platform_name: str, external_id: str, watcher,
          action: str, actor: str) -> dict:
    who = (actor or "").strip()[:200] or "administrator"
    # The identity id is checked again here, where it becomes part of an address.
    if not _is_identity_id(external_id):
        raise SwitchRefused("The platform id kept for this agent is not an agent identity id, so "
                            "nothing was sent.")
    if not _audit("agent_platform_switch_requested", agent_id, platform, action, who):
        raise SwitchRefused(_AUDIT_DOWN, 503)
    try:
        watcher.switch(external_id, enabled=action == "on")
    except WatchError as e:
        message = agent_watch._safe_message(e)
        status = _status_of(message)
        _audit("agent_platform_switch_failed", agent_id, platform, action, who,
               outcome="failed", http_status=status)
        log.warning("agent_watch_switch: %s could not be switched %s on %s", agent_id, action, platform)
        raise SwitchFailed(f"{message}{_NOT_DONE}", status) from None
    except Exception as e:
        # The text of an unexpected failure may hold anything; log its type only.
        log.warning("agent_watch_switch: the change stopped unexpectedly (%s)", type(e).__name__)
        _audit("agent_platform_switch_failed", agent_id, platform, action, who, outcome="failed")
        raise SwitchFailed("The change stopped because of an unexpected problem. The server log has "
                           f"the details.{_NOT_DONE}") from None
    _audit("agent_platform_switched", agent_id, platform, action, who, outcome="switched")
    done = "switched off" if action == "off" else "switched back on"
    return {"ok": True, "platform": platform, "platform_name": platform_name, "action": action,
            "message": f"The agent was {done} on {platform_name}. The next platform check shows it "
                       "as a change to its set-up."}


def _is_identity_id(value: str) -> bool:
    import re
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value))


def _status_of(message: str) -> int | None:
    """The HTTP status a failure message names ("HTTP 403"), for the audit row."""
    import re
    found = re.search(r"HTTP (\d{3})", message)
    return int(found.group(1)) if found else None


def _audit(kind: str, agent_id: str, platform: str, action: str, who: str, **payload) -> bool:
    """One audit row: ids, the action, who asked and the outcome, never a
    message from the platform. A refusal from the audit log propagates."""
    from .audit import audit_event
    return audit_event(kind, agent="agent_watch", external_agent=agent_id, platform=platform,
                       action=action, requested_by=who, **payload)


__all__ = [
    "ACTIONS",
    "SwitchFailed",
    "SwitchRefused",
    "offer",
    "switch",
]
