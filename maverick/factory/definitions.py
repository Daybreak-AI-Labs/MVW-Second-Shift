"""The agent definition as the factory handles it: built from a person's or the model's words, checked with the
runtime's own schema, never stored unchecked.

The model section and the Second Shift section of a definition come from the ``[factory]`` settings, not from a
person or a model: they hold the NAMES of environment variables, never an address or a key.
"""
from __future__ import annotations

import re
from typing import Any

from . import FactoryError
from .settings import GOVERNANCE_ADDRESS_ENV, GOVERNANCE_KEY_ENV, FactorySettings

RISKS = ("low", "medium", "high")
DEFAULT_LIMITS = {"max_steps": 10, "max_tool_calls": 20, "max_seconds": 300, "max_input_chars": 20000}
DEFAULT_COST_LIMIT = 1.0  # dollars per run, used only when the settings give prices
#: Fields a person (or the model) may set; everything else in a definition comes from the server.
EDITABLE = ("name", "description", "instructions", "skills", "limits")
LIMIT_LABELS = {
    "max_steps": "Most steps (model calls) in one run",
    "max_tool_calls": "Most tool calls in one run",
    "max_seconds": "Longest a run may take, in seconds",
    "max_cost_dollars": "Most one run may cost, in dollars",
    "max_input_chars": "Longest input, in characters",
}
_SLUG = re.compile(r"[^a-z0-9]+")


def runtime():
    """The runtime's modules, or a plain error when it is not installed."""
    try:
        from second_shift_runtime import definition, loop, models, skills
    except ImportError as exc:
        from . import NOT_INSTALLED

        raise FactoryError(NOT_INSTALLED, 503) from exc
    return definition, loop, models, skills


def slug(name: str) -> str:
    base = _SLUG.sub("-", str(name or "").lower()).strip("-")[:48].strip("-")
    return base or "agent"


def skill_catalog() -> list[dict[str, Any]]:
    """Every skill the runtime has, with its plain description and its default risk rating."""
    _definition, _loop, _models, skills = runtime()
    out = []
    for name, cls in sorted(skills.registry().items()):
        out.append({"name": name, "description": cls.description, "default_risk": cls.default_risk,
                    "settings": sorted(cls.settings_spec)})
    return out


def default_limits(settings: FactorySettings) -> dict[str, Any]:
    limits: dict[str, Any] = dict(DEFAULT_LIMITS)
    if settings.has_prices:
        limits["max_cost_dollars"] = DEFAULT_COST_LIMIT
    return limits


def assemble(parts: dict[str, Any], *, agent_id: str, version: int, settings: FactorySettings) -> dict[str, Any]:
    """The full definition document: the person's or model's parts plus what the server fixes."""
    limits = dict(default_limits(settings))
    given = parts.get("limits")
    if isinstance(given, dict):
        limits.update(given)
    elif given is not None:
        limits = given  # not an object: the schema refuses it with its own reason
    raw: dict[str, Any] = {
        "id": agent_id,
        "name": parts.get("name"),
        "description": parts.get("description", ""),
        "version": str(version),
        "instructions": parts.get("instructions"),
        "model": settings.model_block(),
        "skills": parts.get("skills", []),
        "limits": limits,
        "governance": {"address_env": GOVERNANCE_ADDRESS_ENV, "agent_key_env": GOVERNANCE_KEY_ENV},
    }
    return raw


def validate(raw: Any):
    """The runtime's checked definition, or a FactoryError with the runtime's plain reason."""
    definition, _loop, _models, _skills = runtime()
    try:
        return definition.parse_definition(raw)
    except definition.DefinitionError as exc:
        raise FactoryError(str(exc), 422) from exc


def clean_skills(value: Any) -> list[dict[str, Any]]:
    """Skills as a list of ``{name, risk?, settings?}``; a bare name is accepted. Anything else is left for the
    schema to refuse with its own reason."""
    if not isinstance(value, list):
        return value  # type: ignore[return-value]
    out: list[Any] = []
    for item in value:
        out.append({"name": item} if isinstance(item, str) else item)
    return out


def summary(raw: dict[str, Any]) -> dict[str, Any]:
    """The parts of a definition worth showing in a list or an approval card."""
    skills = [{"name": s.get("name"), "risk": s.get("risk")} for s in raw.get("skills", []) if isinstance(s, dict)]
    return {"name": raw.get("name"), "description": raw.get("description", ""), "skills": skills,
            "limits": raw.get("limits", {})}


def skill_risks(raw: dict[str, Any]) -> dict[str, str]:
    """Each skill's effective rating: the runtime's rule, so it matches what the agent tells Second Shift."""
    definition = validate(raw)
    _d, _l, _m, skills = runtime()
    return {name: bound.risk for name, bound in skills.resolve_skills(definition.skills).items()}


def highest_risk(risks: dict[str, str]) -> str | None:
    if not risks:
        return None
    return max(risks.values(), key=RISKS.index)
