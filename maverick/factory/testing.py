"""Test runs: each test case goes through the runtime with the configured model, under a governance stand-in.

The stand-in lives inside the server. It records every screen call and allows what the definition's own ratings allow;
no outside agent is created for a test, no run is opened on the Outside agents page, and nothing here counts as the
agent's activity. A test run is bounded by the ``[factory]`` settings: the number of cases, the time a case and the
whole run may take, and the cost of the whole run (a run whose estimate is over the bound is refused before it starts).
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import FactoryError, store
from . import definitions as defs
from . import models as factory_models
from .settings import FactorySettings

log = logging.getLogger("maverick.factory.testing")

MAX_ANSWER_CHARS = 4000
MAX_STEPS_SHOWN = 50
_ACTIVE: dict[str, threading.Thread] = {}
_LOCK = threading.Lock()
#: Tests set this to run inline instead of in a background thread.
RUN_INLINE = False


def is_active(run_id: str) -> bool:
    with _LOCK:
        thread = _ACTIVE.get(run_id)
    return bool(thread and thread.is_alive())


class StandInGovernance:
    """Duck-types the runtime's governance client. Records every screen call; allows a tool the definition lists, at
    the rating the definition gives it, and refuses anything else."""

    def __init__(self, ratings: dict[str, str]):
        self.ratings = ratings
        self.screens: list[dict[str, Any]] = []
        self.report: dict[str, Any] | None = None
        self.stop_reason: str | None = None
        self.goal_id = 0

    def start(self, title: str, summary: str = "", declared: dict[str, str] | None = None) -> int:
        return 0

    def start_beating(self) -> None:
        return None

    def beat(self) -> bool:
        return True

    def screen(self, tool: str, risk: str, detail: str):
        from second_shift_runtime.governance import Decision

        allowed = self.ratings.get(tool) == risk
        self.screens.append({"tool": tool, "risk": risk, "detail": detail[:300], "allowed": allowed})
        return Decision(allowed, "allowed" if allowed else "The tool is not in this agent's definition at that rating.",
                        "" if allowed else "denied")

    def finish(self, report: dict[str, Any]) -> dict[str, Any]:
        self.report = report
        return {"ok": True}

    def close(self) -> None:
        return None


@dataclass
class Outcome:
    ok: bool
    answer: str
    tools: list[str]
    files: list[dict[str, Any]]
    cost: float | None


def evaluate_checks(checks: list[dict[str, Any]], outcome: Outcome) -> list[dict[str, Any]]:
    """Each check with ``passed`` and a plain ``detail`` that says what was found."""
    results = []
    answer = outcome.answer.casefold()
    for check in checks:
        kind, value = check["kind"], check["value"]
        if kind == "uses_skill":
            passed = value in outcome.tools
            detail = f"{value} was used." if passed else f"{value} was not used. Skills used: {', '.join(sorted(set(outcome.tools))) or 'none'}."
        elif kind == "not_uses_skill":
            passed = value not in outcome.tools
            detail = f"{value} was not used." if passed else f"{value} was used, and should not have been."
        elif kind == "answer_contains":
            passed = str(value).casefold() in answer
            detail = "The phrase is in the answer." if passed else "The phrase is not in the answer."
        elif kind == "answer_not_contains":
            passed = str(value).casefold() not in answer
            detail = "The phrase is not in the answer." if passed else "The phrase is in the answer, and should not be."
        elif kind == "makes_file":
            passed = any(str(f["name"]).lower().endswith("." + str(value)) for f in outcome.files)
            detail = f"A .{value} file was made." if passed else f"No .{value} file was made."
        elif kind == "max_cost":
            if outcome.cost is None:
                passed, detail = False, "The cost could not be worked out because the settings give no model prices."
            else:
                passed = outcome.cost < float(value)
                detail = f"The run cost ${outcome.cost:.4f}, " + (f"under ${float(value):g}." if passed else f"not under ${float(value):g}.")
        else:  # pragma: no cover - clean_checks refuses every other kind
            passed, detail = False, "This kind of check is not known."
        results.append({"kind": kind, "value": value, "passed": passed, "detail": detail})
    return results


def estimate_cost(settings: FactorySettings, definition: Any, cases: list[dict[str, Any]]) -> float | None:
    """A rough, deliberately generous estimate of what the whole test run will cost; None without prices."""
    if not settings.has_prices:
        return None
    _d, _l, _m, skills = defs.runtime()
    tool_chars = sum(len(b.skill.description) + len(json.dumps(b.skill.input_schema)) for b in skills.resolve_skills(definition.skills).values())
    steps = max(1, min(definition.limits.max_steps, 4))
    total = 0.0
    for case in cases:
        prompt = (len(definition.instructions) + len(case["input"]) + tool_chars) / 4
        tokens_in = sum(prompt + 1500 * i for i in range(steps))
        tokens_out = steps * min(definition.model.max_output_tokens, 500)
        cost = (tokens_in * settings.input_price_per_million + tokens_out * settings.output_price_per_million) / 1_000_000  # type: ignore[operator]
        cap = definition.limits.max_cost_dollars
        total += min(cost, cap) if cap is not None else cost
    return total


def refusal(record: dict[str, Any], version: dict[str, Any], settings: FactorySettings) -> str | None:
    """Why a test run cannot start now, in plain words, or None."""
    if version["state"] not in ("draft", "tested"):
        return "Only a draft or tested version can be tested."
    cases = record.get("cases") or []
    if not cases:
        return "Write at least one test case first."
    if len(cases) > settings.max_test_cases:
        return f"This agent has {len(cases)} test cases and a test run may have at most {settings.max_test_cases} (the limit is in the settings)."
    tests = version.get("tests")
    if tests and tests.get("status") == "running" and is_active(tests.get("run_id", "")):
        return "Tests are already running on this version."
    return None


def start(fac_id: str, number: int, who: str, settings: FactorySettings) -> dict[str, Any]:
    """Start a test run of one version. Returns the record with the run marked as running."""
    defs.runtime()
    factory_models.require_ready(settings)
    record = store.get(fac_id)
    version = store.find_version(record, number)
    why = refusal(record, version, settings)
    if why:
        raise FactoryError(why, 409)
    if store.latest(record)["number"] != number:
        raise FactoryError("Only the newest version can be tested.", 409)
    if not settings.has_prices and (settings.max_test_run_cost_dollars > 0 or version["definition"]["limits"].get("max_cost_dollars") is not None):
        raise FactoryError("The settings give no model prices (input_price_per_million and output_price_per_million), so the cost of a "
                           "test run cannot be worked out or bounded. Add the prices to the [factory] settings, then run the tests.", 409)
    if version["definition"]["model"] != settings.model_block():
        # The model settings changed since this draft was saved: save a new revision with the current ones, so what is
        # tested is exactly what is recorded.
        _restamp(fac_id, number, who, settings)
        record = store.get(fac_id)
        version = store.find_version(record, number)
    definition = defs.validate(version["definition"])
    estimate = estimate_cost(settings, definition, record["cases"])
    if estimate is not None and estimate > settings.max_test_run_cost_dollars:
        raise FactoryError(f"This test run is estimated to cost about ${estimate:.2f}, over the limit of ${settings.max_test_run_cost_dollars:g} "
                           "in the settings. Remove test cases, lower the agent's step limit or raise the limit, then try again.", 409)
    run_id = uuid.uuid4().hex
    digest, cdigest = version["config_digest"], store.cases_digest(record["cases"])

    def mark(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, number)
        if v["config_digest"] != digest or store.cases_digest(rec["cases"]) != cdigest or v["state"] not in ("draft", "tested"):
            raise FactoryError("The agent changed while the tests were starting. Run them again.", 409)
        running = v.get("tests")
        if running and running.get("status") == "running" and is_active(running.get("run_id", "")):
            raise FactoryError("Tests are already running on this version.", 409)
        v["tests"] = {"run_id": run_id, "status": "running", "config_digest": digest, "cases_digest": cdigest,
                      "started_at": store.now(), "started_by": who, "finished_at": None, "estimated_cost": estimate,
                      "total_cost": 0.0, "results": [], "case_count": len(rec["cases"]), "note": ""}
        store.log(v, who, "Started a test run.")

    saved = store.change(fac_id, who, "tests_started", mark)
    context = contextvars.copy_context()
    thread = threading.Thread(target=lambda: context.run(execute, fac_id, number, run_id, who, settings), name=f"factory-tests-{run_id[:8]}", daemon=True)
    with _LOCK:
        _ACTIVE[run_id] = thread
    thread.start()
    if RUN_INLINE:
        thread.join()
        return store.get(fac_id)
    return saved


def _restamp(fac_id: str, number: int, who: str, settings: FactorySettings) -> None:
    def apply(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, number)
        raw = dict(v["definition"], model=settings.model_block())
        v["definition"], v["config_digest"] = raw, defs.validate(raw).config_digest
        v["revision"] += 1
        v["state"] = "draft"
        v["last_changed_by"], v["last_changed_at"] = who, store.now()
        store.log(v, who, "The model settings changed, so this draft now uses the current ones and needs testing again.")

    store.change(fac_id, who, "draft_saved", apply)


def _run_case(definition: Any, raw: dict[str, Any], case: dict[str, Any], settings: FactorySettings, client: Any,
              remaining_seconds: float, remaining_cost: float | None) -> dict[str, Any]:
    definition_mod, loop, _models, skills = defs.runtime()
    limits = dict(raw["limits"])
    limits["max_seconds"] = max(1.0, min(float(limits["max_seconds"]), settings.max_case_seconds, remaining_seconds))
    if remaining_cost is not None:
        cap = limits.get("max_cost_dollars")
        limits["max_cost_dollars"] = max(0.000001, min(cap, remaining_cost) if cap is not None else remaining_cost)
    bounded = definition_mod.parse_definition(dict(raw, limits=limits))
    standin = StandInGovernance({n: b.risk for n, b in skills.resolve_skills(bounded.skills).items()})
    began = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="factory-test-") as out:
        result = loop.run_agent(bounded, case["input"], Path(out), env=os.environ, model=client, governance=standin)
        files = [f.public() for f in result.files]
    report = standin.report or {}
    outcome = Outcome(result.outcome == "success", result.answer, list(result.tools), files, result.cost_dollars)
    checks = evaluate_checks(case["checks"], outcome)
    if not outcome.ok:
        status = "error"
    else:
        status = "passed" if all(c["passed"] for c in checks) else "failed"
    return {
        "case_id": case["id"], "name": case["name"], "status": status, "checks": checks,
        "reason": result.reason, "answer": result.answer[:MAX_ANSWER_CHARS],
        "steps": [str(s)[:300] for s in (report.get("steps") or [])][:MAX_STEPS_SHOWN],
        "tools": list(result.tools), "screens": standin.screens[:100], "files": files,
        "cost": result.cost_dollars, "input_tokens": result.input_tokens, "output_tokens": result.output_tokens,
        "seconds": round(time.monotonic() - began, 3), "model_steps": result.steps,
    }


def _skipped(case: dict[str, Any], why: str) -> dict[str, Any]:
    return {"case_id": case["id"], "name": case["name"], "status": "error", "checks": [], "reason": why, "answer": "", "steps": [],
            "tools": [], "screens": [], "files": [], "cost": 0.0, "input_tokens": 0, "output_tokens": 0, "seconds": 0.0, "model_steps": 0}


def execute(fac_id: str, number: int, run_id: str, who: str, settings: FactorySettings) -> None:
    """Run every case of one test run, saving each result as it arrives. Never raises: a failure is written to the run."""
    note = ""
    try:
        record = store.get(fac_id)
        version = store.find_version(record, number)
        raw, cases = version["definition"], list(record["cases"])
        definition = defs.validate(raw)
        client = factory_models.build_client(definition.model)
        began, spent = time.monotonic(), 0.0
        for case in cases:
            elapsed = time.monotonic() - began
            if elapsed >= settings.max_test_run_seconds:
                result = _skipped(case, f"Not run: the whole test run reached its {settings.max_test_run_seconds:g} second limit.")
            elif settings.has_prices and spent >= settings.max_test_run_cost_dollars:
                result = _skipped(case, f"Not run: the whole test run reached its ${settings.max_test_run_cost_dollars:g} cost limit.")
            else:
                result = _run_case(definition, raw, case, settings, client, settings.max_test_run_seconds - elapsed,
                                   (settings.max_test_run_cost_dollars - spent) if settings.has_prices else None)
            spent += result["cost"] or 0.0
            _save_result(fac_id, number, run_id, who, result, spent)
    except Exception as exc:  # the run must end with a plain reason, whatever went wrong
        note = str(exc) if isinstance(exc, FactoryError) or type(exc).__name__ == "ModelError" else "The test run stopped because of an unexpected error."
        if not isinstance(exc, FactoryError) and type(exc).__name__ != "ModelError":
            log.exception("test run failed")
    try:
        _finish(fac_id, number, run_id, who, note)
    except Exception:
        log.exception("test run could not be finished")
    finally:
        with _LOCK:
            _ACTIVE.pop(run_id, None)


def _own_run(version: dict[str, Any], run_id: str) -> dict[str, Any] | None:
    tests = version.get("tests")
    return tests if tests and tests.get("run_id") == run_id else None


def _save_result(fac_id: str, number: int, run_id: str, who: str, result: dict[str, Any], spent: float) -> None:
    def apply(rec: dict[str, Any]) -> None:
        tests = _own_run(store.find_version(rec, number), run_id)
        if tests is None:
            return
        tests["results"].append(result)
        tests["total_cost"] = round(spent, 6)

    store.change(fac_id, who, "test_result_saved", apply)


def _finish(fac_id: str, number: int, run_id: str, who: str, note: str) -> None:
    def apply(rec: dict[str, Any]) -> None:
        version = store.find_version(rec, number)
        tests = _own_run(version, run_id)
        if tests is None:
            return
        tests["status"], tests["finished_at"], tests["note"] = "finished", store.now(), note
        passed = (not note and len(tests["results"]) == tests["case_count"] and all(r["status"] == "passed" for r in tests["results"]))
        tests["passed"] = passed
        current = (tests["config_digest"] == version["config_digest"] and tests["cases_digest"] == store.cases_digest(rec["cases"]))
        if passed and current and version["state"] == "draft":
            version["state"] = "tested"
        store.log(version, who, "Tests passed." if passed else "Tests finished with problems.")

    store.change(fac_id, who, "tests_finished", apply)


def settle_interrupted(record: dict[str, Any], who: str = "system") -> dict[str, Any]:
    """A run recorded as running that no thread in this server is working on was cut off (a restart): end it, plainly."""
    stale = [v for v in record["versions"] if v.get("tests") and v["tests"].get("status") == "running" and not is_active(v["tests"].get("run_id", ""))]
    if not stale:
        return record

    def apply(rec: dict[str, Any]) -> None:
        for v in rec["versions"]:
            tests = v.get("tests")
            if tests and tests.get("status") == "running" and not is_active(tests.get("run_id", "")):
                tests.update(status="finished", passed=False, finished_at=store.now(),
                             note="The test run was cut off because the server restarted. Run the tests again.")

    try:
        return store.change(record["id"], who, "tests_finished", apply)
    except FactoryError:
        return record
