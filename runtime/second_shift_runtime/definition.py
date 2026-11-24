"""The agent definition: one JSON document that says what the agent is.

Secrets are never in it. The model endpoint, the model key, the Second Shift
address and the agent key are given as the NAMES of environment variables.
Anything not listed here is refused, so a typo cannot silently change how an
agent behaves.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

PROVIDERS = ("foundry_openai", "foundry_anthropic")
RISKS = ("low", "medium", "high")  # lowest to highest, as Second Shift ranks them

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class DefinitionError(ValueError):
    """The definition is not usable. The message says what to fix."""


@dataclass(frozen=True)
class ModelSettings:
    provider: str
    endpoint_env: str
    api_key_env: str
    deployment: str
    max_output_tokens: int = 2000
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None


@dataclass(frozen=True)
class SkillEntry:
    name: str
    settings: dict[str, Any] = field(default_factory=dict)
    risk: str | None = None  # may only raise the skill's default rating


@dataclass(frozen=True)
class Limits:
    max_steps: int = 10
    max_tool_calls: int = 20
    max_seconds: float = 300.0
    max_cost_dollars: float | None = None
    max_input_chars: int = 20000


@dataclass(frozen=True)
class GovernanceSettings:
    address_env: str
    agent_key_env: str


@dataclass(frozen=True)
class AgentDefinition:
    id: str
    name: str
    description: str
    instructions: str
    model: ModelSettings
    governance: GovernanceSettings
    version: str = "1"
    skills: tuple[SkillEntry, ...] = ()
    limits: Limits = field(default_factory=Limits)
    # The canonical form the digest is taken over (kept so it is computed once).
    canonical: str = ""

    @property
    def config_digest(self) -> str:
        return hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()


def _fail(where: str, message: str) -> DefinitionError:
    return DefinitionError(f"{where}: {message}")


def _object(value: Any, where: str, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(where, "must be a JSON object.")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise _fail(where, f"unknown field {unknown[0]!r}. Allowed fields: {', '.join(sorted(allowed))}.")
    missing = sorted(required - set(value))
    if missing:
        raise _fail(where, f"missing required field {missing[0]!r}.")
    return value


def _text(value: Any, where: str, *, maximum: int, empty_ok: bool = False) -> str:
    if not isinstance(value, str):
        raise _fail(where, "must be text.")
    if not empty_ok and not value.strip():
        raise _fail(where, "must not be empty.")
    if len(value) > maximum:
        raise _fail(where, f"is too long ({len(value)} characters; the limit is {maximum}).")
    return value


def _env_name(value: Any, where: str) -> str:
    name = _text(value, where, maximum=128)
    if not _ENV_NAME.match(name):
        raise _fail(where, "must be the NAME of an environment variable (letters, digits and underscores), "
                           "never the secret or address itself.")
    return name


def _number(value: Any, where: str, *, low: float, high: float, integer: bool = False) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _fail(where, "must be a number.")
    if integer and (not isinstance(value, int)):
        if float(value).is_integer():
            value = int(value)
        else:
            raise _fail(where, "must be a whole number.")
    if not (low <= value <= high):
        raise _fail(where, f"must be between {low:g} and {high:g}.")
    return value


def _model(raw: Any) -> ModelSettings:
    data = _object(raw, "model", {"provider", "endpoint_env", "api_key_env", "deployment", "max_output_tokens",
                                  "input_price_per_million", "output_price_per_million"},
                   {"provider", "endpoint_env", "api_key_env", "deployment"})
    provider = _text(data["provider"], "model.provider", maximum=40)
    if provider not in PROVIDERS:
        raise _fail("model.provider", f"must be one of: {', '.join(PROVIDERS)}.")
    prices: dict[str, float | None] = {}
    for key in ("input_price_per_million", "output_price_per_million"):
        prices[key] = float(_number(data[key], f"model.{key}", low=0, high=1_000_000)) if key in data else None
    if (prices["input_price_per_million"] is None) != (prices["output_price_per_million"] is None):
        raise _fail("model", "give both input_price_per_million and output_price_per_million, or neither. "
                             "Prices are your own figures; the runtime has none built in.")
    return ModelSettings(
        provider=provider,
        endpoint_env=_env_name(data["endpoint_env"], "model.endpoint_env"),
        api_key_env=_env_name(data["api_key_env"], "model.api_key_env"),
        deployment=_text(data["deployment"], "model.deployment", maximum=200),
        max_output_tokens=int(_number(data.get("max_output_tokens", 2000), "model.max_output_tokens",
                                      low=16, high=200_000, integer=True)),
        **prices,
    )


def _skills(raw: Any) -> tuple[SkillEntry, ...]:
    if not isinstance(raw, list):
        raise _fail("skills", "must be a list.")
    entries, seen = [], set()
    for i, item in enumerate(raw):
        where = f"skills[{i}]"
        data = _object(item, where, {"name", "settings", "risk"}, {"name"})
        name = _text(data["name"], f"{where}.name", maximum=64)
        if name in seen:
            raise _fail(where, f"skill {name!r} is listed twice.")
        seen.add(name)
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            raise _fail(f"{where}.settings", "must be a JSON object.")
        risk = data.get("risk")
        if risk is not None and risk not in RISKS:
            raise _fail(f"{where}.risk", f"must be one of: {', '.join(RISKS)}.")
        entries.append(SkillEntry(name=name, settings=settings, risk=risk))
    return tuple(entries)


def _limits(raw: Any) -> Limits:
    data = _object(raw, "limits", {"max_steps", "max_tool_calls", "max_seconds", "max_cost_dollars", "max_input_chars"}, set())
    base = Limits()
    cost = data.get("max_cost_dollars")
    return Limits(
        max_steps=int(_number(data.get("max_steps", base.max_steps), "limits.max_steps", low=1, high=200, integer=True)),
        max_tool_calls=int(_number(data.get("max_tool_calls", base.max_tool_calls), "limits.max_tool_calls",
                                   low=0, high=1000, integer=True)),
        max_seconds=float(_number(data.get("max_seconds", base.max_seconds), "limits.max_seconds", low=1, high=86_400)),
        max_cost_dollars=None if cost is None else float(_number(cost, "limits.max_cost_dollars", low=0, high=1_000_000)),
        max_input_chars=int(_number(data.get("max_input_chars", base.max_input_chars), "limits.max_input_chars",
                                    low=1, high=1_000_000, integer=True)),
    )


def parse_definition(raw: Any) -> AgentDefinition:
    """Check a decoded JSON document and return the definition, or raise DefinitionError."""
    data = _object(raw, "definition",
                   {"id", "name", "description", "version", "instructions", "model", "skills", "limits", "governance"},
                   {"id", "name", "instructions", "model", "governance"})
    agent_id = _text(data["id"], "id", maximum=64)
    if not _ID.match(agent_id):
        raise _fail("id", "may use letters, digits, dots, dashes and underscores only (up to 64 characters).")
    gov = _object(data["governance"], "governance", {"address_env", "agent_key_env"}, {"address_env", "agent_key_env"})
    definition = AgentDefinition(
        id=agent_id,
        name=_text(data["name"], "name", maximum=200),
        description=_text(data.get("description", ""), "description", maximum=2000, empty_ok=True),
        version=_text(data.get("version", "1"), "version", maximum=100),
        instructions=_text(data["instructions"], "instructions", maximum=50_000),
        model=_model(data["model"]),
        governance=GovernanceSettings(_env_name(gov["address_env"], "governance.address_env"),
                                      _env_name(gov["agent_key_env"], "governance.agent_key_env")),
        skills=_skills(data.get("skills", [])),
        limits=_limits(data.get("limits", {})),
    )
    if definition.limits.max_cost_dollars is not None and definition.model.input_price_per_million is None:
        raise _fail("limits.max_cost_dollars", "a cost limit needs model prices (input_price_per_million and "
                                               "output_price_per_million) so the cost can be estimated.")
    # Check skill names, settings and risk ratings now, so a bad definition fails before any run starts.
    from .skills import resolve_skills
    resolve_skills(definition.skills)
    canonical = json.dumps(_normalised(definition), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _with_canonical(definition, canonical)


def _normalised(d: AgentDefinition) -> dict[str, Any]:
    return {
        "id": d.id, "name": d.name, "description": d.description, "version": d.version,
        "instructions": d.instructions,
        "model": {
            "provider": d.model.provider, "endpoint_env": d.model.endpoint_env, "api_key_env": d.model.api_key_env,
            "deployment": d.model.deployment, "max_output_tokens": d.model.max_output_tokens,
            "input_price_per_million": d.model.input_price_per_million,
            "output_price_per_million": d.model.output_price_per_million,
        },
        "skills": [{"name": s.name, "settings": s.settings, "risk": s.risk} for s in d.skills],
        "limits": {
            "max_steps": d.limits.max_steps, "max_tool_calls": d.limits.max_tool_calls, "max_seconds": d.limits.max_seconds,
            "max_cost_dollars": d.limits.max_cost_dollars, "max_input_chars": d.limits.max_input_chars,
        },
        "governance": {"address_env": d.governance.address_env, "agent_key_env": d.governance.agent_key_env},
    }


def _with_canonical(d: AgentDefinition, canonical: str) -> AgentDefinition:
    from dataclasses import replace
    return replace(d, canonical=canonical)


def load_definition(path: str) -> AgentDefinition:
    """Read a definition file."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as exc:
        raise DefinitionError(f"The definition file {path!r} could not be read: {exc.strerror or exc}.") from exc
    except json.JSONDecodeError as exc:
        raise DefinitionError(f"The definition file {path!r} is not valid JSON (line {exc.lineno}, column {exc.colno}).") from exc
    return parse_definition(raw)
