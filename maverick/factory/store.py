"""Versioned agent records, kept in the governed record store.

One record per agent holds its test cases and its numbered versions. A version is edited only while it is a draft
(or tested); once released it never changes again, except to be retired. Editing a released agent starts the next
number. Every change goes through :func:`change`, which applies it with compare-and-swap on the record's revision and
retries a lost race, so two people saving at once never overwrite each other silently.

Why the governed record store: it already gives durable records on the local backend and on PostgreSQL, compare-and-swap
revisions, tenant scoping and a signed audit event for every write that is not lost when the audit writer is down. The
factory needs exactly that and nothing else, so it adds no table and no migration.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from typing import Any

from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict

from . import FactoryError
from . import definitions as defs
from .settings import FactorySettings

STORE = GovernedRecordStore("factory_agents", "FAC", "factory_agent")

STATES = ("draft", "tested", "waiting_for_approval", "released", "retired")
STATE_LABELS = {"draft": "Draft", "tested": "Tested", "waiting_for_approval": "Waiting for approval",
                "released": "Released", "retired": "Retired"}
MAX_HISTORY = 100
MAX_CASES_HARD = 200
MAX_RETRIES = 6
CHECK_KINDS = {
    "uses_skill": "Must use the skill",
    "not_uses_skill": "Must not use the skill",
    "answer_contains": "The answer must contain",
    "answer_not_contains": "The answer must not contain",
    "makes_file": "Must produce a file of type",
    "max_cost": "Must cost less than (dollars)",
}
FILE_TYPES = ("docx", "pptx", "xlsx")


def now() -> float:
    return time.time()


def digest_of(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def cases_digest(cases: list[dict[str, Any]]) -> str:
    return digest_of([{"id": c["id"], "input": c["input"], "checks": c["checks"]} for c in cases])


def person(value: Any) -> str:
    from maverick.safety.dual_control import person_key

    return person_key(value)


def get(fac_id: str) -> dict[str, Any]:
    try:
        found = STORE.get(fac_id)
    except ValueError:
        found = None
    if found is None:
        raise FactoryError("There is no such agent.", 404)
    return found


def list_agents() -> list[dict[str, Any]]:
    return sorted(STORE.list(), key=lambda r: r.get("created_at", 0), reverse=True)


def change(fac_id: str, who: str, action: str, fn: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
    """Apply ``fn`` to the agent's record and save it, retrying a lost race. ``fn`` may raise FactoryError to refuse.
    Returns the saved record."""
    last: Exception | None = None
    for _ in range(MAX_RETRIES):
        current = get(fac_id)
        try:
            saved = STORE.update(fac_id, fn, expected_revision=int(current["revision"]), action=action, actor=who)
        except RecordConflict as exc:
            last = exc
            continue
        if saved is None:
            raise FactoryError("There is no such agent.", 404)
        return saved
    raise FactoryError("Someone else is changing this agent right now. Reload and try again.", 409) from last


def log(version: dict[str, Any], who: str, what: str) -> None:
    version.setdefault("history", []).append({"at": now(), "by": who, "what": what})
    del version["history"][:-MAX_HISTORY]


def open_version(record: dict[str, Any]) -> dict[str, Any] | None:
    """The version being worked on: the newest, unless it is already released or retired."""
    versions = record.get("versions") or []
    if versions and versions[-1]["state"] in ("draft", "tested", "waiting_for_approval"):
        return versions[-1]
    return None


def latest(record: dict[str, Any]) -> dict[str, Any]:
    return record["versions"][-1]


def released_version(record: dict[str, Any]) -> dict[str, Any] | None:
    return next((v for v in reversed(record["versions"]) if v["state"] == "released"), None)


def find_version(record: dict[str, Any], number: int) -> dict[str, Any]:
    found = next((v for v in record["versions"] if v["number"] == number), None)
    if found is None:
        raise FactoryError("There is no such version.", 404)
    return found


def _unique_agent_id(name: str) -> str:
    taken = {str(r.get("agent_id")) for r in STORE.list()}
    base = defs.slug(name)
    candidate, n = base, 1
    while candidate in taken:
        n += 1
        candidate = f"{base[:60]}-{n}"
    return candidate


def _new_version(number: int, raw: dict[str, Any], digest: str, who: str) -> dict[str, Any]:
    stamp = now()
    version = {
        "number": number, "state": "draft", "revision": 1, "definition": raw, "config_digest": digest,
        "made_by": who, "last_changed_by": who, "last_changed_at": stamp, "created_at": stamp,
        "tests": None, "approval": None, "released_at": None, "retired_at": None, "history": [],
    }
    log(version, who, f"Created version {number}.")
    return version


def create_agent(who: str, brief: dict[str, Any], parts: dict[str, Any], settings: FactorySettings) -> dict[str, Any]:
    """Save a new agent with version 1 as a draft. The definition is checked first; a bad one saves nothing."""
    agent_id = _unique_agent_id(str(parts.get("name") or ""))
    raw = defs.assemble(parts, agent_id=agent_id, version=1, settings=settings)
    digest = defs.validate(raw).config_digest
    record = {
        "id": STORE.new_id(), "agent_id": agent_id, "name": raw["name"], "created_by": who,
        "brief": brief, "versions": [_new_version(1, raw, digest, who)], "cases": [], "enrollment": None,
    }
    return STORE.create(record, action="agent_created", actor=who)


def _editable_parts(raw: dict[str, Any]) -> dict[str, Any]:
    return {key: json.loads(json.dumps(raw.get(key))) for key in defs.EDITABLE}


def edit(fac_id: str, who: str, parts: dict[str, Any], settings: FactorySettings, *,
         base_version: int, base_revision: int) -> dict[str, Any]:
    """Save the person's edit as a new revision of the working draft (or as the first revision of the next version).

    ``base_version`` and ``base_revision`` are what the person was looking at; if the agent has moved on, nothing is saved."""
    unknown = sorted(set(parts) - set(defs.EDITABLE))
    if unknown:
        raise FactoryError(f"{unknown[0]!r} cannot be changed here.", 422)

    def apply(record: dict[str, Any]) -> None:
        tip = latest(record)
        if tip["number"] != base_version or tip["revision"] != base_revision:
            raise FactoryError("Someone else changed this agent after you opened it. Reload the page to see their change, then make yours again.", 409)
        if tip["state"] == "waiting_for_approval":
            raise FactoryError("This version is waiting for approval and cannot be changed. Ask the approver to send it back, then edit it.", 409)
        if tip["tests"] and tip["tests"].get("status") == "running" and _test_active(tip):
            raise FactoryError("Tests are running on this version. Wait for them to finish before changing it.", 409)
        merged = _editable_parts(tip["definition"])
        merged.update({k: v for k, v in parts.items()})
        if "skills" in parts:
            merged["skills"] = defs.clean_skills(parts["skills"])
        number = tip["number"] if tip["state"] in ("draft", "tested") else tip["number"] + 1
        raw = defs.assemble(merged, agent_id=record["agent_id"], version=number, settings=settings)
        digest = defs.validate(raw).config_digest
        if tip["state"] in ("draft", "tested"):
            if digest == tip["config_digest"] and raw == tip["definition"]:
                return  # nothing changed, so no new revision
            tip["definition"], tip["config_digest"] = raw, digest
            tip["revision"] += 1
            tip["state"] = "draft"
            tip["last_changed_by"], tip["last_changed_at"] = who, now()
            log(tip, who, f"Saved revision {tip['revision']}; it needs testing again.")
        else:
            fresh = _new_version(number, raw, digest, who)
            log(fresh, who, f"Started from version {tip['number']}.")
            record["versions"].append(fresh)
        record["name"] = raw["name"]

    return change(fac_id, who, "draft_saved", apply)


def _test_active(version: dict[str, Any]) -> bool:
    from . import testing

    return testing.is_active(version["tests"].get("run_id", ""))


# -- test cases ------------------------------------------------------------------------------------------------------

def clean_checks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise FactoryError("Give every test case at least one check, so there is something to pass or fail.", 422)
    if len(value) > 20:
        raise FactoryError("A test case may have at most 20 checks.", 422)
    out = []
    for item in value:
        if not isinstance(item, dict) or item.get("kind") not in CHECK_KINDS:
            raise FactoryError("A check must be one of: " + "; ".join(CHECK_KINDS.values()) + ".", 422)
        kind, raw = item["kind"], item.get("value")
        if kind == "max_cost":
            try:
                amount = float(raw)
            except (TypeError, ValueError):
                raise FactoryError("The cost limit must be a number of dollars.", 422) from None
            if not (0 < amount <= 100_000) or amount != amount:
                raise FactoryError("The cost limit must be more than zero.", 422)
            out.append({"kind": kind, "value": amount})
            continue
        text = " ".join(str(raw if raw is not None else "").split())
        if not text or len(text) > 500:
            raise FactoryError("Fill in every check (up to 500 characters).", 422)
        if kind == "makes_file":
            text = text.lower().lstrip(".")
            if text not in FILE_TYPES:
                raise FactoryError("A file check must name one of these types: " + ", ".join(FILE_TYPES) + ".", 422)
        out.append({"kind": kind, "value": text})
    return out


def _clean_case(data: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    name = " ".join(str(data.get("name") or "").split())[:200]
    text = str(data.get("input") or "")
    if not text.strip():
        raise FactoryError("Write the input the agent should be given.", 422)
    if len(text) > 20_000:
        raise FactoryError("The input is too long (20000 characters at most).", 422)
    return name, text, clean_checks(data.get("checks"))


def _cases_changed(record: dict[str, Any], who: str, what: str) -> None:
    """Changed test cases mean the tests on every open version no longer cover what is checked now."""
    for version in record["versions"]:
        if version["state"] == "tested":
            version["state"] = "draft"
            log(version, who, what + " The version needs testing again.")


def _require_open_for_cases(record: dict[str, Any]) -> None:
    tip = latest(record)
    if tip["state"] == "waiting_for_approval":
        raise FactoryError("This agent is waiting for approval, so its test cases cannot change now.", 409)
    if tip["tests"] and tip["tests"].get("status") == "running" and _test_active(tip):
        raise FactoryError("Tests are running. Wait for them to finish before changing the test cases.", 409)


def add_case(fac_id: str, who: str, data: dict[str, Any], settings: FactorySettings) -> dict[str, Any]:
    name, text, checks = _clean_case(data)

    def apply(record: dict[str, Any]) -> None:
        _require_open_for_cases(record)
        if len(record["cases"]) >= settings.max_test_cases:
            raise FactoryError(f"An agent may have at most {settings.max_test_cases} test cases (the limit is in the settings).", 409)
        record["cases"].append({"id": STORE.new_id().split("-", 1)[1][:12], "name": name or f"Case {len(record['cases']) + 1}",
                                "input": text, "checks": checks, "added_by": who})
        _cases_changed(record, who, "A test case was added.")

    return change(fac_id, who, "test_case_added", apply)


def update_case(fac_id: str, who: str, case_id: str, data: dict[str, Any]) -> dict[str, Any]:
    name, text, checks = _clean_case(data)

    def apply(record: dict[str, Any]) -> None:
        _require_open_for_cases(record)
        case = next((c for c in record["cases"] if c["id"] == case_id), None)
        if case is None:
            raise FactoryError("There is no such test case.", 404)
        case.update(name=name or case["name"], input=text, checks=checks)
        _cases_changed(record, who, "A test case was changed.")

    return change(fac_id, who, "test_case_changed", apply)


def delete_case(fac_id: str, who: str, case_id: str) -> dict[str, Any]:
    def apply(record: dict[str, Any]) -> None:
        _require_open_for_cases(record)
        kept = [c for c in record["cases"] if c["id"] != case_id]
        if len(kept) == len(record["cases"]):
            raise FactoryError("There is no such test case.", 404)
        record["cases"] = kept
        _cases_changed(record, who, "A test case was removed.")

    return change(fac_id, who, "test_case_removed", apply)


# -- what a version has earned ----------------------------------------------------------------------------------------

def gate(record: dict[str, Any], version: dict[str, Any]) -> dict[str, Any]:
    """Whether this exact version may be submitted for release, and if not, why in plain words."""
    cases = record.get("cases") or []
    tests = version.get("tests")
    if not cases:
        return {"open": False, "reason": "Write at least one test case first. A version is released only when its tests pass."}
    if not tests or tests.get("status") != "finished":
        return {"open": False, "reason": "Run the tests on this version first."}
    if tests.get("config_digest") != version["config_digest"]:
        return {"open": False, "reason": "This version changed after its last test run. Run the tests again."}
    if tests.get("cases_digest") != cases_digest(cases):
        return {"open": False, "reason": "The test cases changed after the last test run. Run the tests again."}
    results = tests.get("results") or []
    if len(results) != len(cases) or any(r.get("status") != "passed" for r in results):
        failed = sum(1 for r in results if r.get("status") != "passed")
        return {"open": False, "reason": f"{failed or 'Some'} test case(s) did not pass. Every case must pass before a version can be released."}
    return {"open": True, "reason": ""}
