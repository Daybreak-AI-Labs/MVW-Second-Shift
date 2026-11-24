"""What changed on an agent's home platform, in plain words.

A platform check hands drift detection a fingerprint, which says only that
"something changed". Beside it the check keeps a small description of the
fields that define the agent's set-up, so a person can be told which ones:

* ``describe`` / ``clean`` -- build, or re-validate, a description. A
  description holds short labels (model and tool names, a version, a state,
  timestamps), true/false flags, bounded lists of labels, and for anything
  long only a short digest of it. Instruction text and any other free text an
  agent's author wrote is never kept; a value that does not fit its field, is
  too long or looks like a secret is dropped. Every list and string is bounded.
* ``digest`` -- the short digest kept in place of long text.
* ``compare`` -- the field-level difference between two descriptions and a
  one-paragraph summary of it for an alert, the audit log and the agent page.

What it does not do. It never reads a platform and never decides whether a
change matters; ``agent_drift`` does that. A description written before this
module existed is simply absent, and ``compare`` then says that details were
not recorded instead of guessing. What a platform does not report is left out
of a description and said so in the summary, never filled in.

The set of fields for each platform is the set its check already reads to make
the fingerprint (see the module of each check for where the platform
documents them).
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

SCHEMA = 1

#: What a platform is called to a person.
PLATFORM_NAMES = {
    "entra_agent_id": "Microsoft Entra Agent ID",
    "foundry": "Microsoft Foundry",
    "copilot_studio": "Microsoft Copilot Studio",
    "servicenow": "ServiceNow",
    "workday": "Workday",
}

#: Value kinds. ``text``: a short label. ``time``: a timestamp as text.
#: ``flag``: true or false. ``digest``: a short digest of something long.
#: ``set``: a bounded list of labels whose order means nothing. ``map``: label
#: to digest, for the settings of each item of a ``set``.
_KINDS = ("text", "time", "flag", "digest", "set", "map")

_MAX_LABEL = 80
_MAX_NAME = 120
_MAX_ITEMS = 50
_MAX_SHOWN = 5
_MAX_SIDE = 300
_MAX_SUMMARY = 800
_MAX_CHANGES = 30
_DIGEST_HEX = 16

_HEX64 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{16}")
_TIME = re.compile(r"[0-9][0-9T:.+\-Z ]{3,39}")
_ISO_MINUTE = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})")

#: Per platform, in the order a summary lists them: (key, plain label, kind,
#: phrase). A phrase, when given, says a change to a ``time`` or ``text``
#: field in a sentence of its own; ``{after}`` is the new value.
#: ``name`` is the one field every platform has, shown first.
_NAME = ("name", "name", "text", None)
FIELDS: dict[str, tuple[tuple[str, str, str, str | None], ...]] = {
    # https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0
    "entra_agent_id": (
        _NAME,
        ("enabled", "enabled", "flag", None),
        ("blueprint", "blueprint", "text", None),
        ("disabled_by_microsoft", "disabled by Microsoft", "text", None),
        ("identity_type", "identity type", "text", None),
    ),
    # https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/toolbox
    # https://learn.microsoft.com/azure/azure-arc/agents-tools-foundry-local/reference/agents-api-reference#agent-versions
    "foundry": (
        _NAME,
        ("version", "version", "text", None),
        ("state", "state", "text", None),
        ("kind", "agent kind", "text", None),
        ("model", "model", "text", None),
        ("tools", "tool", "set", None),
        ("tool_settings", "tool settings", "map", None),
        ("instructions", "instructions", "digest", None),
    ),
    # https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/bot
    "copilot_studio": (
        _NAME,
        ("state", "state", "text", None),
        ("status_code", "status code", "text", None),
        ("published", "published", "time", "published again at {after}"),
        ("modified", "last edited", "time", "edited at {after}"),
    ),
    # https://servicenow.github.io/sdk/api/aiagent-api
    "servicenow": (
        _NAME,
        ("active", "active", "flag", None),
        ("version", "published version", "text", None),
        ("versions", "version", "set", None),
        ("version_settings", "version settings", "map", None),
        ("instructions", "instructions", "digest", None),
        ("tools", "tool", "set", None),
        ("tool_settings", "tool settings", "map", None),
        ("agent_type", "agent type", "text", None),
        ("channel", "channel", "text", None),
        ("record_type", "record type", "text", None),
        ("parent", "parent agent", "text", None),
        ("public", "available to everyone", "flag", None),
        ("run_as_user", "runs as user", "text", None),
        ("advanced_mode", "advanced mode", "flag", None),
        ("agent_learning", "agent learning", "flag", None),
        ("role", "role text", "digest", None),
        ("description", "description", "digest", None),
        ("condition", "run condition", "digest", None),
        ("context_script", "context script", "digest", None),
    ),
    # https://workday.github.io/asor/versions/v1.2.json
    "workday": (
        _NAME,
        ("version", "version", "text", None),
        ("provider", "provider", "text", None),
        ("platform_id", "platform", "text", None),
        ("capabilities", "capability", "set", None),
        ("extended_card", "extended card", "flag", None),
        ("skills", "skill", "set", None),
        ("skill_definitions", "skill definitions", "digest", None),
        ("workday_config", "Workday resources and run modes", "digest", None),
        ("description", "description", "digest", None),
        ("input_modes", "input modes", "digest", None),
        ("output_modes", "output modes", "digest", None),
        ("url", "address", "digest", None),
        ("external_agent_id", "external agent id", "digest", None),
        ("external_tenant_id", "external tenant id", "digest", None),
    ),
}

#: What a platform does not say, added to a summary that has something to say.
_NOT_KNOWN = {
    "copilot_studio": "Copilot Studio does not say what was edited, only when.",
    "workday": "Workday does not say who changed the definition or when.",
}


def digest(value: Any) -> str | None:
    """The short digest kept in place of long text. Text is hashed here; a
    64-character hex digest (a watcher's own hash) is shortened. ``None`` for
    nothing."""
    if value is None:
        return None
    if isinstance(value, str) and _HEX64.fullmatch(value):
        return "sha256:" + value[:_DIGEST_HEX]
    if not isinstance(value, str):
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:_DIGEST_HEX]


def describe(platform: str, values: Mapping[str, Any]) -> dict:
    """A description of one agent's set-up from ``values`` (field key to
    value), keeping only the platform's fields, each in its own bounded form.
    Anything that does not fit is left out, never repaired into something
    else. Long text must be given as a ``digest`` already."""
    fields = {}
    for key, _label, kind, _phrase in FIELDS.get(platform, ()):
        value = _clean_value(kind, values.get(key), _MAX_NAME if key == "name" else _MAX_LABEL)
        if value is not None:
            fields[key] = value
    return {"v": SCHEMA, "fields": fields} if fields else {}


def clean(platform: str, description: Any) -> dict:
    """``description`` as stored: validated again, so a value that was edited
    on disk or came from an older layout cannot put free text on a page.
    ``{}`` when it holds nothing usable."""
    if not isinstance(description, Mapping) or description.get("v") != SCHEMA:
        return {}
    raw = description.get("fields")
    return describe(platform, raw) if isinstance(raw, Mapping) else {}


def _clean_value(kind: str, value: Any, limit: int) -> Any:
    if kind == "flag":
        return value if isinstance(value, bool) else None
    if kind == "digest":
        return value if isinstance(value, str) and _DIGEST.fullmatch(value) else None
    if kind in ("text", "time"):
        return _label(value, limit, time=kind == "time")
    if kind == "set":
        return _label_list(value)
    if kind == "map":
        return _label_map(value)
    return None


def _label(value: Any, limit: int, *, time: bool = False) -> str | None:
    """One short, printable, one-line label, or ``None`` when the value is not
    one: wrong kind, empty, too long, or shaped like a secret."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    if not text or len(text) > limit or not text.isprintable():
        return None  # not printable also refuses a line break or a tab
    if time and not _TIME.fullmatch(text):
        return None
    return None if _looks_secret(text) else text


def _label_list(value: Any) -> list[str] | None:
    if not isinstance(value, (list, tuple)):
        return None
    labels = {label for item in value[:_MAX_ITEMS * 2] if (label := _label(item, _MAX_LABEL))}
    return sorted(labels)[:_MAX_ITEMS]


def _label_map(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    kept: dict[str, str] = {}
    for key, item in value.items():
        label = _label(key, _MAX_LABEL)
        if label and isinstance(item, str) and _DIGEST.fullmatch(item):
            kept[label] = item
    return dict(sorted(kept.items())[:_MAX_ITEMS])


def _looks_secret(text: str) -> bool:
    try:
        from .safety.secret_detector import redact
        return redact(text)[0] != text
    except Exception:
        return True  # cannot check it, so do not keep it


def compare(platform: str, before: Any, after: Any) -> dict:
    """The difference between the approved description and the current one.

    Returns ``{"recorded", "summary", "changes", "not_known"}``. ``recorded``
    is false when either side holds no description (a record from before
    descriptions were kept); the summary then says so. Each change is ``{"field",
    "label", "kind", "before", "after", "text"}``: the strings are short and
    safe to show, ``text`` is its phrase in the summary. A field only one side
    has is a change too, worded as "now reported" or "no longer reported"."""
    name_of = PLATFORM_NAMES.get(platform, "its platform")
    old, new = clean(platform, before).get("fields"), clean(platform, after).get("fields")
    if old is None or new is None:
        return {"recorded": False, "summary": "", "changes": [], "not_known": [],
                "details": "Details were not recorded for this change."}
    changes = []
    for key, label, kind, phrase in FIELDS.get(platform, ()):
        found = _difference(key, label, kind, phrase, old.get(key), new.get(key))
        if found:
            changes.append(found)
    not_known = [] if not changes or platform not in _NOT_KNOWN else [_NOT_KNOWN[platform]]
    who = new.get("name") or old.get("name") or "This agent"
    return {"recorded": True, "summary": _summary(who, name_of, changes, not_known),
            "changes": changes[:_MAX_CHANGES], "not_known": not_known, "details": ""}


def _difference(key: str, label: str, kind: str, phrase: str | None, was: Any, now: Any) -> dict | None:
    if was == now:
        return None
    if kind == "set":
        return _set_change(key, label, was, now)
    if kind == "map":
        return _map_change(key, label, was, now)
    show = {"flag": _yes_no, "digest": _fingerprint, "time": _moment}.get(kind, str)
    before = None if was is None else show(was)
    after = None if now is None else show(now)
    return _change(key, label, kind, before, after, _sentence(label, kind, phrase, before, after, now))


def _sentence(label: str, kind: str, phrase: str | None, before: str | None, after: str | None,
              now: Any) -> str:
    if after is None:
        return f"{label} is no longer reported (was {before})"
    if before is None:
        return f"{label} is now reported: {after}"
    if kind == "digest":
        return (f"{label} changed (Second Shift keeps a fingerprint of the {label}, "
                "not the text)")
    if phrase:
        return phrase.format(after=after)
    return f"{label} {before} -> {after}"


def _set_change(key: str, label: str, was: Any, now: Any) -> dict | None:
    if was is None or now is None:
        shown = _join(now if now is not None else was)
        text = (f"{label}s are now reported: {shown}" if was is None
                else f"{label}s are no longer reported (were {shown})")
        return _change(key, label, "set", None if was is None else _join(was),
                       None if now is None else _join(now), text)
    added, removed = sorted(set(now) - set(was)), sorted(set(was) - set(now))
    parts = []
    if added:
        parts.append(f"{_plural(label, len(added))} added: {_join(added)}")
    if removed:
        parts.append(f"{_plural(label, len(removed))} removed: {_join(removed)}")
    return _change(key, label, "set", _join(was), _join(now), "; ".join(parts)) if parts else None


def _map_change(key: str, label: str, was: Any, now: Any) -> dict | None:
    if was is None or now is None:
        return _change(key, label, "map", None if was is None else _fingerprint_count(was),
                       None if now is None else _fingerprint_count(now),
                       f"{label} are now reported" if was is None else f"{label} are no longer reported")
    changed = sorted(name for name in set(was) & set(now) if was[name] != now[name])
    if not changed:
        return None
    return _change(key, label, "map", _join(changed), _join(changed),
                   f"{label} changed: {_join(changed)} (Second Shift keeps a fingerprint of the "
                   "settings, not the settings)")


def _change(key: str, label: str, kind: str, before: str | None, after: str | None, text: str) -> dict:
    return {"field": key, "label": label, "kind": kind, "before": _side(before),
            "after": _side(after), "text": text[:_MAX_SIDE * 2]}


def _side(value: str | None) -> str | None:
    return None if value is None else value[:_MAX_SIDE]


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _fingerprint(value: str) -> str:
    return "fingerprint " + value.split(":", 1)[-1][:8]


def _fingerprint_count(value: Mapping[str, str]) -> str:
    return f"{len(value)} recorded"


def _moment(value: str) -> str:
    """A timestamp the way a person reads it (UTC, to the minute) when it is in
    the usual form, else as the platform wrote it."""
    found = _ISO_MINUTE.match(value)
    return f"{found.group(1)} {found.group(2)} UTC" if found else value


def _plural(label: str, count: int) -> str:
    return label if count == 1 else f"{label}s"


def _join(items: Any) -> str:
    items = list(items)
    shown = ", ".join(items[:_MAX_SHOWN])
    return shown + (f" and {len(items) - _MAX_SHOWN} more" if len(items) > _MAX_SHOWN else "")


def _summary(who: str, platform_name: str, changes: list[dict], not_known: list[str]) -> str:
    if not changes:
        body = ("its set-up changed in a way this check cannot describe, because the fields it "
                "reads are the same")
    else:
        shown = [change["text"] for change in changes[:_MAX_SHOWN]]
        if len(changes) > _MAX_SHOWN:
            shown.append(f"and {len(changes) - _MAX_SHOWN} more changes")
        body = "; ".join(shown)
    text = f"{who} changed on {platform_name}: {body}."
    if not_known:
        text += " " + " ".join(not_known)
    return text[:_MAX_SUMMARY]


__all__ = [
    "FIELDS",
    "PLATFORM_NAMES",
    "clean",
    "compare",
    "describe",
    "digest",
]
