"""Release: a tested version is submitted, a different person approves it on the Approvals page, and Second Shift
then enrolls the agent as an outside agent and marks the version released.

The approval is an ordinary approval with its own provenance, ``factory_release``, so it shows on the Approvals page
and in Teams and every existing decision rule applies (the card's binding, the confirmation step for high risk,
the separate-approver rule). On top of those, the person who last changed the version, and the person who submitted
it, can never approve it. Releasing after approval is automatic; it is done by :func:`settle`, which runs right after a
decision and again whenever a factory page is read, so a decision made anywhere (a chat card, say) is never missed.

No access key is made here. Keys are made in the export step.
"""
from __future__ import annotations

import logging
from typing import Any

from . import FactoryError, store
from . import definitions as defs

log = logging.getLogger("maverick.factory.release")

PROVENANCE = "factory_release"
ACTION_PREFIX = "factory_release:"
APPROVAL_TTL_SECONDS = 7 * 24 * 3600.0
PLATFORM = "custom"
SAME_PERSON = "You changed or submitted this version, so someone else must approve it."


def parse_action(action: str) -> tuple[str, int] | None:
    """``factory_release:<agent record id>:<version number>`` -> (record id, number)."""
    parts = str(action or "").split(":")
    if len(parts) != 3 or parts[0] != "factory_release" or not parts[2].isdigit():
        return None
    return parts[1], int(parts[2])


def approver_refusal(approval: Any, who: str) -> str:
    """Why ``who`` may not approve this release, or "". Fails closed: a request that cannot be read is refused."""
    try:
        target = parse_action(getattr(approval, "action", ""))
        if target is None:
            return "This release request could not be read, so it cannot be approved."
        record = store.get(target[0])
        version = store.find_version(record, target[1])
        barred = {store.person(version.get("last_changed_by")), store.person((version.get("approval") or {}).get("submitted_by")),
                  store.person(getattr(approval, "requested_by", ""))} - {""}
        return SAME_PERSON if store.person(who) in barred else ""
    except Exception:
        log.warning("release request could not be checked", exc_info=True)
        return "This release request could not be checked, so it cannot be approved now."


def _world():
    from maverick.world_model import open_world

    return open_world()


def _card_lines(record: dict[str, Any], version: dict[str, Any], risks: dict[str, str]) -> list[str]:
    raw = version["definition"]
    tests = version.get("tests") or {}
    passed = sum(1 for r in tests.get("results", []) if r.get("status") == "passed")
    skills = ", ".join(f"{n} ({r} risk)" for n, r in sorted(risks.items())) or "none"
    limits = raw["limits"]
    return [
        f"Agent: {raw['name']} (version {version['number']})",
        f"What it is for: {record['brief'].get('purpose', '')[:200]}" if record.get("brief") else f"What it is for: {raw.get('description', '')[:200]}",
        f"Skills and their risk: {skills}",
        f"Limits: {limits['max_steps']} steps, {limits['max_tool_calls']} tool calls, {limits['max_seconds']:g} seconds a run",
        f"Tests: {passed} of {len(tests.get('results', []))} test cases passed on exactly this version",
        f"Last changed by {version['last_changed_by']}; submitted by {(version.get('approval') or {}).get('submitted_by', '')}",
    ]


def _create_approval(record: dict[str, Any], version: dict[str, Any], who: str, risks: dict[str, str]) -> tuple[int, str, float]:
    from maverick.approval_cards import decode_approval_detail, encode_operation_approval_detail
    from maverick.safety.dual_control import required_approvals

    number, digest = version["number"], version["config_digest"]
    risk = "high" if "high" in risks.values() else "medium"
    action = f"{ACTION_PREFIX}{record['id']}:{number}"
    name = version["definition"]["name"]
    detail = encode_operation_approval_detail(
        action=action, summary=f"Release the agent {name}, version {number}",
        target_label=f"Agent {name}, version {number}",
        target={"factory_agent": record["id"], "agent_id": record["agent_id"], "version": number, "config_digest": digest},
        parameters={"config_digest": digest, "skills": risks, "limits": version["definition"]["limits"]},
        parameter_summary=_card_lines(record, version, risks), actor=who, role="operator",
        known_effects=[f"Enrolls {record['agent_id']} as an outside agent on the Custom platform, allowed to use only the skills listed, at those ratings.",
                       "Makes this version the approved configuration, so a run that reports a different one shows up as drift.",
                       "Makes no access key. Keys are created later."],
        unresolved_assumptions=["The tests cover what the agent will really be asked to do."],
        before="The agent is not released.", after=f"Version {number} of the agent is released and governed from its first action.",
        irreversible=False, ttl_seconds=APPROVAL_TTL_SECONDS)
    card = decode_approval_detail(detail) or {}
    approval_id = _world().create_approval(action, risk=risk, detail=detail, provenance=PROVENANCE,
                                           approvals_required=required_approvals(risk), requested_by=who)
    return approval_id, str(card.get("binding_sha256", "")), float(card.get("expires_at", 0.0))


def submit(fac_id: str, number: int, who: str) -> dict[str, Any]:
    """Ask for approval to release a version. Only a version whose tests all passed on exactly this version goes."""
    settle(fac_id)
    record = store.get(fac_id)
    version = store.find_version(record, number)
    if version["state"] != "tested":
        raise FactoryError("Only a tested version can be submitted for release." if version["state"] != "waiting_for_approval"
                           else "This version is already waiting for approval.", 409)
    closed = store.gate(record, version)
    if not closed["open"]:
        raise FactoryError(closed["reason"], 409)
    risks = defs.skill_risks(version["definition"])
    digest = version["config_digest"]

    def hold(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, number)
        if v["state"] != "tested" or v["config_digest"] != digest or not store.gate(rec, v)["open"]:
            raise FactoryError("The version changed while it was being submitted. Check it and submit again.", 409)
        v["state"] = "waiting_for_approval"
        v["approval"] = {"id": None, "submitted_by": who, "submitted_at": store.now(), "config_digest": digest, "outcome": ""}
        store.log(v, who, "Submitted for release.")

    held = store.change(fac_id, who, "release_submitted", hold)
    version = store.find_version(held, number)
    try:
        approval_id, binding, expires = _create_approval(held, version, who, risks)
    except Exception as exc:
        _back_to_tested(fac_id, number, who, "The request for approval could not be made, so the submission was withdrawn.")
        if isinstance(exc, FactoryError):
            raise
        log.warning("release approval could not be created", exc_info=True)
        raise FactoryError("The request for approval could not be made. Nothing was submitted; try again.", 503) from exc

    def attach(rec: dict[str, Any]) -> None:
        a = store.find_version(rec, number)["approval"]
        a.update(id=approval_id, binding_sha256=binding, expires_at=expires)

    return store.change(fac_id, who, "release_approval_requested", attach)


def _back_to_tested(fac_id: str, number: int, who: str, why: str, *, outcome: str = "") -> None:
    def apply(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, number)
        if v["state"] == "waiting_for_approval":
            v["state"] = "tested"
            if v.get("approval"):
                v["approval"]["outcome"] = outcome or "withdrawn"
                v["approval"]["note"] = why
            store.log(v, who, why)

    store.change(fac_id, who, "release_returned", apply)


def _enroll(record: dict[str, Any], version: dict[str, Any], approvers: list[str]) -> dict[str, Any]:
    """Enroll (or update) the agent as an outside agent. Tools are its skills with their ratings; the wall time is the
    definition's own; the highest rating is the riskiest action allowed."""
    from maverick import external_agents

    raw = version["definition"]
    risks = defs.skill_risks(raw)
    previous = released_tools(record)
    removed = sorted(previous - set(risks))
    try:
        summary = external_agents.enroll(
            record["agent_id"], PLATFORM, description=str(raw.get("description") or raw["name"])[:500],
            owner=str(record["created_by"]), allow_tools=[f"{n}:{r}" for n, r in sorted(risks.items())], deny_tools=removed or None,
            max_risk=defs.highest_risk(risks), max_wall_seconds=float(raw["limits"]["max_seconds"]),
            enrolled_by=", ".join(approvers))
    except external_agents.ExternalAgentsError as exc:
        raise FactoryError(f"The agent was approved but could not be enrolled: {exc}", 409) from exc
    return summary


def released_tools(record: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for v in record["versions"]:
        if v["state"] in ("released", "retired"):
            out |= {s["name"] for s in v["definition"].get("skills", [])}
    return out


def _approve_drift(record: dict[str, Any], version: dict[str, Any], who: str) -> str:
    """Make this version's digest the approved configuration for drift. Returns a note, empty when it worked."""
    try:
        from maverick import agent_drift

        agent_drift.approve_declared_configuration(
            record["agent_id"], version=str(version["number"]), config_digest=version["config_digest"],
            model=version["definition"]["model"]["deployment"], actor=who)
        return ""
    except Exception:
        log.warning("drift baseline not updated for a released agent", exc_info=True)
        return "The new configuration could not be recorded as approved for drift checks. Approve the baseline on the agent's page."


def settle(fac_id: str, who: str = "system") -> dict[str, Any]:
    """Act on the decision of any release approval this agent is waiting for. Safe to call at any time and more than once."""
    from . import testing

    record = testing.settle_interrupted(store.get(fac_id))
    for version in list(record["versions"]):
        approval = version.get("approval")
        if version["state"] != "waiting_for_approval" or not approval:
            continue
        if approval.get("id") is None:
            # The request was never created (the server stopped mid-submit): put the version back, so it can be submitted again.
            _back_to_tested(fac_id, version["number"], who, "The request for approval was never made. Submit it again.")
            continue
        try:
            row = _world().approval_state(int(approval["id"]))
        except Exception:
            log.warning("approval could not be read", exc_info=True)
            continue  # unreadable now: leave it waiting and look again later (never release on a guess)
        if row is None:
            _back_to_tested(fac_id, version["number"], who, "The approval request no longer exists. Submit it again.")
        elif row["status"] == "approved":
            _release(fac_id, version["number"], list(row.get("approvers") or []), who)
        elif row["status"] == "denied":
            _back_to_tested(fac_id, version["number"], who, "The approver sent this version back. Read their reason on the Approvals page, "
                            "make your changes and test again.", outcome="denied")
        elif float(approval.get("expires_at") or 0) and store.now() > float(approval["expires_at"]):
            _back_to_tested(fac_id, version["number"], who, "The approval request expired. Submit it again.", outcome="expired")
    return store.get(fac_id)


def _release(fac_id: str, number: int, approvers: list[str], who: str) -> None:
    record = store.get(fac_id)
    version = store.find_version(record, number)
    if version["state"] != "waiting_for_approval":
        return
    approval = version["approval"]
    barred = {store.person(version.get("last_changed_by")), store.person(approval.get("submitted_by"))} - {""}
    if not approvers or any(store.person(a) in barred for a in approvers):
        # Never release on an approval the rules would have refused; send it back so it is asked again properly.
        _back_to_tested(fac_id, number, who, "It was approved by someone who changed or submitted it, which is not allowed. Submit it again for someone else to approve.",
                        outcome="refused")
        return
    if approval.get("config_digest") != version["config_digest"] or not store.gate(record, version)["open"]:
        _back_to_tested(fac_id, number, who, "The version no longer matches what was approved. Test it and submit it again.", outcome="stale")
        return
    other = store.released_version(record)
    try:
        _enroll(record, version, approvers)
    except FactoryError as exc:
        _note_release_problem(fac_id, number, who, str(exc))
        return
    drift_note = _approve_drift(record, version, approvers[-1])

    def apply(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, number)
        if v["state"] != "waiting_for_approval":
            return
        stamp = store.now()
        if other is not None:
            old = store.find_version(rec, other["number"])
            if old["state"] == "released":
                old["state"], old["retired_at"] = "retired", stamp
                store.log(old, "system", f"Replaced by version {number}.")
        v["state"], v["released_at"] = "released", stamp
        v["approval"].update(outcome="approved", approved_by=approvers, release_problem="", drift_note=drift_note)
        rec["enrollment"] = {"external_agent_id": rec["agent_id"], "platform": PLATFORM, "enrolled_version": number,
                             "config_digest": v["config_digest"], "enrolled_at": stamp, "status": "enrolled"}
        store.log(v, who, f"Approved by {', '.join(approvers)} and released.")

    store.change(fac_id, who, "version_released", apply)


def _note_release_problem(fac_id: str, number: int, who: str, text: str) -> None:
    def apply(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, number)
        if v.get("approval"):
            v["approval"]["release_problem"] = text

    try:
        store.change(fac_id, who, "release_problem", apply)
    except FactoryError:
        log.warning("release problem could not be noted", exc_info=True)


def settle_all() -> None:
    """Settle every agent that is waiting on an approval. One that cannot be read does not stop the rest."""
    for record in store.list_agents():
        if any(v["state"] == "waiting_for_approval" for v in record["versions"]) or any(
                v.get("tests") and v["tests"].get("status") == "running" for v in record["versions"]):
            try:
                settle(record["id"])
            except Exception:
                log.warning("agent could not be settled", exc_info=True)


def on_decision(approval_id: int) -> None:
    """Called right after any approval decision is recorded; releases at once if it was a factory release."""
    try:
        approval = _world().get_approval(int(approval_id))
        target = parse_action(getattr(approval, "action", "")) if approval is not None and approval.provenance == PROVENANCE else None
        if target:
            settle(target[0])
    except Exception:
        log.warning("release not settled after a decision", exc_info=True)


def retire(fac_id: str, who: str) -> dict[str, Any]:
    """Retire the released version and cut the agent off: its enrollment is removed, so its keys stop working."""
    from maverick import external_agents

    record = store.get(fac_id)
    version = store.released_version(record)
    if version is None:
        raise FactoryError("Only a released agent can be retired.", 409)
    try:
        external_agents.unenroll(record["agent_id"], actor=who)
    except Exception as exc:
        log.warning("retire could not remove the enrollment", exc_info=True)
        raise FactoryError("The agent could not be cut off, so it was not retired. Try again, or remove it on the Outside agents page.", 503) from exc

    def apply(rec: dict[str, Any]) -> None:
        v = store.find_version(rec, version["number"])
        if v["state"] == "released":
            v["state"], v["retired_at"] = "retired", store.now()
            store.log(v, who, "Retired.")
        if rec.get("enrollment"):
            rec["enrollment"]["status"] = "removed"

    return store.change(fac_id, who, "version_retired", apply)
