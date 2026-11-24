"""What a person is told, step by step, to connect one outside agent.

The text is plain language and mirrors ``docs/connect-an-agent.md``. Each
platform's guide says where a step has not been tested in a real tenant. This
module returns text only: it creates no key, calls no platform and changes no
setting; the page does those through the existing endpoints.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from . import external_agents as xa

log = logging.getLogger("maverick.connect_guide")

DOC = "docs/connect-an-agent.md"

_KEY_STEP = {
    "title": "Create the access key",
    "body": "Press Create access key. The key is shown once; copy it straight away. Creating another key "
            "replaces this one at once.",
}

_API_STEPS = [
    _KEY_STEP,
    {"title": "Give the platform the connection file",
     "body": "Download the connection file from this page and import it where {where}. It describes the two "
             "things the agent does: ask Second Shift before a risky action (a screening call) and report each "
             "finished task (a run report). Keep the access key in the place the platform keeps secrets, and "
             "send it as a bearer key with every call."},
    {"title": "Make the agent ask first",
     "body": "{how} The Python runtime and client kits are coming; until then the connection file and "
             "the notes in " + DOC + " are the way in."},
]

_WHERE = {
    "foundry": ("Microsoft Foundry keeps tool definitions",
                "In your Foundry agent, add the connection file as an OpenAPI tool and store the key as a connection secret."),
    "servicenow": ("ServiceNow keeps its outbound REST message or Flow Designer actions",
                   "In ServiceNow, call the two addresses from a Flow Designer action or a REST message, with the key "
                   "kept in a credential record."),
    "workday": ("Workday keeps its integrations",
                "In Workday, call the two addresses from an integration or an extend app, with the key kept as a secret."),
    "custom": ("your agent's runtime reads tool or API descriptions",
               "In your agent's code, call the screening address before each risky action and the run address when "
               "a task ends; the connection file lists both."),
}

_DEFAULT_WHERE = ("your platform imports API descriptions",
                  "In your platform, call the screening address before each risky action and the run address when a "
                  "task ends; the connection file lists both.")

_UNTESTED = {
    "foundry": "These steps have not been tested in a real Microsoft Foundry project.",
    "servicenow": "These steps have not been tested in a real ServiceNow instance.",
    "workday": "These steps have not been tested in a real Workday tenant.",
    "copilot": "The per-agent steps have not been tested in a real Copilot Studio environment.",
}
_UNTESTED_DEFAULT = "These steps have not been tested in a real tenant on this platform."


def _gate_environments() -> list[str]:
    """The environments the Copilot Studio gate covers, or ``[]`` when the
    setting is absent or not a list of text."""
    try:
        from .config import load_config
        section = (load_config() or {}).get("copilot_studio_gate", {})
        found = section.get("environments") if isinstance(section, dict) else None
    except Exception:
        log.warning("connect_guide: the Copilot Studio gate setting could not be read", exc_info=True)
        return []
    if not isinstance(found, list):
        return []
    return [str(e).strip() for e in found if isinstance(e, str) and e.strip()]


def _host(text: str) -> str:
    return re.sub(r"^https?://", "", text.strip().casefold()).strip("/")


def _gate_state(external_ref: str) -> str:
    """``covered``, ``none`` or ``maybe`` (the gate exists but the agent has
    no record on its platform to tell which environment it is in)."""
    envs = [_host(e) for e in _gate_environments()]
    if not envs:
        return "none"
    ref = external_ref.partition(":")[2].partition("/")[0].strip().casefold()
    if not ref:
        return "maybe"
    return "covered" if any(ref == e or ref.startswith(e + ".") for e in envs) else "none"


def guide_for(platform: str, *, external_ref: str = "", gate: str | None = None) -> dict[str, Any]:
    """``{"platform", "label", "kind", "gate", "steps", "untested"}`` for one platform.

    ``kind`` is ``api`` (the connection file and the API), ``copilot_gate``
    (nothing to do per agent) or ``copilot_manual`` (per-agent steps)."""
    label = xa.PLATFORMS.get(platform, "Custom / other runtime")
    untested = _UNTESTED.get(platform, _UNTESTED_DEFAULT)
    if platform != "copilot":
        where, how = _WHERE.get(platform, _DEFAULT_WHERE)
        steps = [{"title": s["title"], "body": s["body"].format(where=where, how=how)} for s in _API_STEPS]
        return {"platform": platform, "label": label, "kind": "api", "gate": "none", "steps": steps,
                "untested": untested}
    gate = gate or _gate_state(external_ref)
    if gate == "covered":
        return {"platform": platform, "label": label, "kind": "copilot_gate", "gate": gate, "untested": untested,
                "steps": [{"title": "No setup needed for this agent",
                           "body": "There is nothing to do for this agent. Its Copilot Studio environment is covered by the Copilot Studio gate, so "
                                   "its agents are checked without a key of their own. You do not need to "
                                   "create an access key for it. Press Check again if you want Second Shift to look "
                                   "for a call."}]}
    steps = [
        {"title": "Check whether the gate covers it",
         "body": ("An administrator has turned the Copilot Studio gate on for some environments. If this agent "
                  "lives in one of them there is nothing more to do; otherwise carry on below. ")
         if gate == "maybe" else
         "The Copilot Studio gate is not turned on for this agent's environment, so it needs its own key."},
        _KEY_STEP,
        {"title": "Add the connection in Copilot Studio",
         "body": "In Copilot Studio, open the agent, add a tool from an OpenAPI file and import the connection file "
                 "from this page. Choose bearer-key sign-in and paste the access key there."},
        {"title": "Make the agent ask first",
         "body": "In the agent's instructions, name the screening tool as the first thing to use before any "
                 "action that changes something. Details are in " + DOC + "."},
    ]
    return {"platform": platform, "label": label, "kind": "copilot_manual", "gate": gate, "steps": steps,
            "untested": untested}


def all_guides() -> list[dict[str, Any]]:
    """Every guide the page may show: one per platform, and Copilot Studio in
    each of its three cases (``gate`` is ``covered``, ``maybe`` or ``none``)."""
    out = [guide_for(key) for key in xa.PLATFORMS if key != "copilot"]
    return out + [guide_for("copilot", gate=g) for g in ("covered", "maybe", "none")]


def gate_for(platform: str, external_ref: str) -> str:
    """Which Copilot Studio guide an agent gets; ``none`` for every other platform."""
    return _gate_state(external_ref or "") if platform == "copilot" else "none"
