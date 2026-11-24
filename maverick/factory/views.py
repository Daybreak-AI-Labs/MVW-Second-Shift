"""What the pages and the API show about an agent, built from its record. Plain data, no secrets: a definition holds
only the NAMES of environment variables."""
from __future__ import annotations

from typing import Any

from . import store


def tests_view(record: dict[str, Any], version: dict[str, Any]) -> dict[str, Any] | None:
    tests = version.get("tests")
    if not tests:
        return None
    stale = (tests.get("config_digest") != version["config_digest"]
             or tests.get("cases_digest") != store.cases_digest(record.get("cases") or []))
    results = tests.get("results") or []
    return {**tests, "stale": bool(stale and tests.get("status") != "running"),
            "passed_count": sum(1 for r in results if r.get("status") == "passed"), "result_count": len(results)}


def version_view(record: dict[str, Any], version: dict[str, Any]) -> dict[str, Any]:
    approval = version.get("approval") or {}
    return {
        "number": version["number"], "state": version["state"], "state_label": store.STATE_LABELS[version["state"]],
        "revision": version["revision"], "definition": version["definition"], "config_digest": version["config_digest"],
        "made_by": version["made_by"], "last_changed_by": version["last_changed_by"], "last_changed_at": version["last_changed_at"],
        "created_at": version["created_at"], "released_at": version.get("released_at"), "retired_at": version.get("retired_at"),
        "tests": tests_view(record, version), "gate": store.gate(record, version),
        "approval": {k: approval.get(k) for k in ("id", "submitted_by", "submitted_at", "expires_at", "outcome", "note",
                                                   "approved_by", "release_problem", "drift_note")} if approval else None,
        "history": version.get("history", [])[-20:],
    }


def agent_view(record: dict[str, Any]) -> dict[str, Any]:
    tip = store.latest(record)
    released = store.released_version(record)
    return {
        "id": record["id"], "agent_id": record["agent_id"], "name": record["name"], "created_by": record["created_by"],
        "brief": record.get("brief") or {}, "state": tip["state"], "state_label": store.STATE_LABELS[tip["state"]],
        "tip": tip["number"], "released": released["number"] if released else None, "enrollment": record.get("enrollment"),
        "cases": record.get("cases") or [], "versions": [version_view(record, v) for v in record["versions"]],
        "revision": record["revision"], "updated_at": record.get("updated_at"),
    }


def summary_view(record: dict[str, Any]) -> dict[str, Any]:
    tip = store.latest(record)
    released = store.released_version(record)
    return {
        "id": record["id"], "agent_id": record["agent_id"], "name": record["name"],
        "description": tip["definition"].get("description", ""), "state": tip["state"], "state_label": store.STATE_LABELS[tip["state"]],
        "tip": tip["number"], "released": released["number"] if released else None, "created_by": record["created_by"],
        "updated_at": record.get("updated_at"), "skills": [s["name"] for s in tip["definition"].get("skills", [])],
    }
