"""Skills: the things an agent can do besides think.

A skill has a name, a description, a JSON-schema input, a default risk rating
and ``run(args, context)``. The risk rating is what the loop tells Second Shift
before the skill runs; a definition may raise it but never lower it.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import httpx

from ..definition import RISKS, DefinitionError, SkillEntry


class SkillError(Exception):
    """The skill could not do what was asked. The message goes back to the model as the tool result."""


@dataclass(frozen=True)
class FileInfo:
    name: str
    size: int
    sha256: str
    path: Path

    def public(self) -> dict[str, Any]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


@dataclass
class SkillResult:
    text: str
    files: list[FileInfo] = field(default_factory=list)


@dataclass
class SkillContext:
    """What a skill may use. ``output_dir`` is the only place it may write."""

    output_dir: Path
    env: Mapping[str, str] = field(default_factory=dict)
    # Test seams: a fake network transport and a fake DNS lookup.
    transport: httpx.BaseTransport | None = None
    resolver: Callable[[str], list[str]] | None = None


class Skill:
    name: ClassVar[str]
    description: ClassVar[str]
    input_schema: ClassVar[dict[str, Any]]
    default_risk: ClassVar[str] = "low"
    #: setting name -> (type, default, low, high); anything else is refused.
    settings_spec: ClassVar[dict[str, tuple[type, Any, float, float]]] = {}

    def __init__(self, settings: Mapping[str, Any] | None = None):
        self.settings = check_settings(self.name, self.settings_spec, settings or {})

    def describe(self, args: dict[str, Any]) -> str:
        """A short plain summary of what the call will do, for Second Shift and the person approving it.
        Never the raw arguments: they can hold long or private text."""
        return f"Run {self.name}."

    def run(self, args: dict[str, Any], context: SkillContext) -> SkillResult:
        raise NotImplementedError


def check_settings(skill: str, spec: dict[str, tuple[type, Any, float, float]], given: Mapping[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(given) - set(spec))
    if unknown:
        allowed = ", ".join(sorted(spec)) or "none"
        raise DefinitionError(f"skills.{skill}.settings: unknown setting {unknown[0]!r}. Allowed settings: {allowed}.")
    out: dict[str, Any] = {}
    for key, (kind, default, low, high) in spec.items():
        value = given.get(key, default)
        if kind is str:
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise DefinitionError(f"skills.{skill}.settings.{key}: must be short text.")
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not (low <= value <= high):
                raise DefinitionError(f"skills.{skill}.settings.{key}: must be a number between {low:g} and {high:g}.")
            value = kind(value)
        out[key] = value
    return out


def registry() -> dict[str, type[Skill]]:
    # Imported here so that a missing optional library can never break importing the package.
    from .documents import CreatePresentation, CreateSpreadsheet, CreateWordDocument
    from .search import WebSearch
    from .web import FetchWebPage

    return {cls.name: cls for cls in (FetchWebPage, WebSearch, CreateWordDocument, CreatePresentation, CreateSpreadsheet)}


@dataclass(frozen=True)
class BoundSkill:
    skill: Skill
    risk: str


def resolve_skills(entries: tuple[SkillEntry, ...]) -> dict[str, BoundSkill]:
    """Build the skills a definition lists. Unknown names, bad settings and lowered risk ratings are refused."""
    known = registry()
    bound: dict[str, BoundSkill] = {}
    for entry in entries:
        cls = known.get(entry.name)
        if cls is None:
            raise DefinitionError(f"skills: there is no skill called {entry.name!r}. Available skills: {', '.join(sorted(known))}.")
        risk = cls.default_risk
        if entry.risk is not None:
            if RISKS.index(entry.risk) < RISKS.index(cls.default_risk):
                raise DefinitionError(f"skills.{entry.name}.risk: {entry.risk!r} is lower than the skill's own rating "
                                      f"({cls.default_risk!r}). A definition may raise a rating, never lower it.")
            risk = entry.risk
        bound[entry.name] = BoundSkill(cls(entry.settings), risk)
    return bound


def write_output_file(output_dir: Path, stem: str, extension: str, writer: Callable[[Path], None], max_bytes: int) -> FileInfo:
    """Write one generated file inside ``output_dir`` under a name this code makes up.

    The model never supplies a path: ``stem`` is reduced to letters, digits and dashes."""
    import re
    import uuid

    safe = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")[:40] or "file"
    output_dir.mkdir(parents=True, exist_ok=True)
    root = output_dir.resolve()
    target = root / f"{safe}-{uuid.uuid4().hex[:8]}.{extension}"
    if target.parent != root:  # cannot happen with the name above; kept as the guard it is
        raise SkillError("The file name was not safe.")
    writer(target)
    size = target.stat().st_size
    if size > max_bytes:
        target.unlink()
        raise SkillError(f"The file would be {size} bytes, over the {max_bytes} byte limit. Ask for less content.")
    return FileInfo(target.name, size, hashlib.sha256(target.read_bytes()).hexdigest(), target)
