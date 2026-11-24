"""Teams cards and the other-approver rule for people whose role comes only from Entra.

The directory (Microsoft Graph) is ``entra_kit.Graph``; Teams, the approval
rules, the role list and the world model are the real ones, set up as in
``test_teams_approvals``. Nothing here reaches Microsoft.
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from tests.new import entra_kit as kit
from tests.new.entra_kit import PEOPLE, Graph
from tests.new.test_teams_approvals import (  # noqa: F401 -- fixtures shared with the Teams tests
    AAD,
    ROLES,
    SERVICE_URL,
    TENANT,
    _click,
    _link,
    _message_text,
    _park,
    _status,
    bot,
    env,
    inline_background,
    rsa_key,
    transport,
    world,
)

ERIN, FRANK = PEOPLE["erin"], PEOPLE["frank"]
AAD["erin"], AAD["frank"] = ERIN, FRANK
NOBODY_ELSE = {"user:alice": "approver", "user:carol": "viewer"}


@pytest.fixture(autouse=True)
def directory(env, monkeypatch, tmp_path):
    """Entra directory on, a Graph that knows nobody yet, and a clock the tests move."""
    from maverick import agent_watch, entra_directory

    monkeypatch.setenv("GRAPH_TENANT", kit.TENANT)
    monkeypatch.setenv("GRAPH_CLIENT", kit.CLIENT)
    monkeypatch.setenv("GRAPH_SECRET", kit.SECRET)
    monkeypatch.delenv("MAVERICK_ENTRA_DIRECTORY", raising=False)
    env.configure(extra=kit.CONFIG.replace("{extra}", ""))
    env.roster(NOBODY_ELSE)
    entra_directory.reset_cache()
    agent_watch._TOKENS.clear()
    clock = kit.Clock()
    monkeypatch.setattr(entra_directory, "_monotonic", clock.monotonic)
    monkeypatch.setattr(entra_directory, "_sleep", clock.sleep)
    graph = kit.serve(monkeypatch, Graph())
    graph.clock = clock
    yield graph
    entra_directory.reset_cache()
    agent_watch._TOKENS.clear()


def _recognised(monkeypatch, *people: str) -> None:
    """These people signed in with Entra and have written to the bot: Second
    Shift knows them as ``user:<name>-sub`` and can post to their chat."""
    from maverick import teams_identity
    from maverick_dashboard import subject_directory

    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)
    for who in people:
        subject_directory.record_login(f"{who}-sub", [AAD[who]])
        teams_identity.remember_conversation(AAD[who], {
            "service_url": SERVICE_URL, "conversation_id": f"19:{who}", "tenant_id": TENANT})


def _approver(graph: Graph, *people: str, role: str = "SecondShift.Approver") -> None:
    graph.assignments = [kit.assignment(PEOPLE[p], role) for p in people]


# ----------------------------------------------------------------- cards


def test_a_card_goes_to_a_person_whose_role_comes_only_from_entra_and_their_click_is_decided(
        directory, env, world, bot, transport, monkeypatch):
    from maverick_dashboard import teams_bot

    _recognised(monkeypatch, "erin")
    _link("alice")
    _approver(directory, "erin")
    approval_id, binding = _park(world)
    results = teams_bot.post_approval(approval_id, bot=bot, world=world)
    assert {r["to"] for r in results} == {"user:alice", "user:erin-sub"} and all(r["ok"] for r in results)

    answer = _click(bot, "approve", approval_id, binding, who="erin")
    assert "Approved by" in _message_text(answer)
    approval = world.get_approval(approval_id)
    assert approval.status == "approved" and approval.decided_by == "user:erin-sub"


def test_the_card_is_sent_and_decided_through_a_group_assignment_too(directory, world, bot, transport, monkeypatch):
    from maverick_dashboard import teams_bot

    _recognised(monkeypatch, "erin")
    directory.assignments = [kit.assignment(kit.GROUP, "SecondShift.Approver", "Group")]
    directory.groups = {kit.GROUP: [kit.member(ERIN)]}
    approval_id, binding = _park(world)
    assert [r["to"] for r in teams_bot.post_approval(approval_id, bot=bot, world=world)] == ["user:erin-sub"]
    assert "Approved by" in _message_text(_click(bot, "reject", approval_id, binding, who="erin")) \
        or _status(world, approval_id) == "denied"


def test_with_the_directory_off_nothing_changes_for_that_person(directory, env, world, bot, transport, monkeypatch):
    from maverick_dashboard import teams_bot

    env.configure(extra=kit.CONFIG.replace("enable = true", "enable = false").replace("{extra}", ""))
    _recognised(monkeypatch, "erin")
    _link("alice")
    _approver(directory, "erin")
    approval_id, binding = _park(world)
    assert [r["to"] for r in teams_bot.post_approval(approval_id, bot=bot, world=world)] == ["user:alice"]
    refused = _click(bot, "approve", approval_id, binding, who="erin")
    assert "can't open this request" in _message_text(refused) and _status(world, approval_id) == "pending"
    assert directory.requests == []  # not one call to Microsoft


def test_a_role_that_maps_to_no_approval_gets_no_card_and_is_refused_as_before(
        directory, world, bot, transport, monkeypatch):
    from maverick_dashboard import approval_decisions, teams_bot

    _recognised(monkeypatch, "erin")
    _approver(directory, "erin", role="SecondShift.Viewer")
    approval_id, binding = _park(world)
    assert teams_bot.post_approval(approval_id, bot=bot, world=world) == []
    with pytest.raises(approval_decisions.ApprovalDecisionRefused) as refused:
        approval_decisions.decide_from_channel(
            approval_id=approval_id, status="approved", principal="user:erin-sub", binding=binding,
            channel="teams", world=world)
    assert "approver role" in refused.value.detail and _status(world, approval_id) == "pending"


def test_a_role_stored_for_the_person_comes_before_the_one_from_entra(directory, env, world, bot, monkeypatch):
    _recognised(monkeypatch, "erin")
    env.roster({**NOBODY_ELSE, "user:erin-sub": "viewer"})
    _approver(directory, "erin", role="SecondShift.Admin")
    approval_id, binding = _park(world)
    refused = _click(bot, "approve", approval_id, binding, who="erin")
    assert _status(world, approval_id) == "pending" and "Approved by" not in _message_text(refused)


def test_every_existing_check_still_applies_to_that_person(directory, world, bot, monkeypatch):
    _recognised(monkeypatch, "erin")
    _approver(directory, "erin")
    approval_id, binding = _park(world, risk="high")
    refused = _click(bot, "approve", approval_id, binding, who="erin")
    assert "read what this action will do" in _message_text(refused) and _status(world, approval_id) == "pending"
    stale = _click(bot, "approve", approval_id, "f" * 64, who="erin", activity_id="s", acknowledged="true")
    assert _status(world, approval_id) == "pending" and "Approved by" not in _message_text(stale)
    done = _click(bot, "approve", approval_id, binding, who="erin", activity_id="d", acknowledged="true")
    assert "Approved by" in _message_text(done)


def test_a_protected_settings_change_is_still_decided_on_the_web_only(directory, world, bot, monkeypatch):
    from maverick_dashboard import approval_decisions

    _recognised(monkeypatch, "erin")
    _approver(directory, "erin")
    approval_id, binding = _park(world, provenance="settings_quorum", requested_by="user:alice")
    with pytest.raises(approval_decisions.ApprovalDecisionRefused):
        approval_decisions.decide_from_channel(
            approval_id=approval_id, status="approved", principal="user:erin-sub", binding=binding,
            channel="teams", world=world)
    assert _status(world, approval_id) == "pending"


# --------------------------------------------- removed roles and failures


def test_a_person_whose_entra_role_was_removed_is_refused_once_the_cache_has_expired(
        directory, env, world, bot, transport, monkeypatch):
    from maverick_dashboard import teams_bot

    _recognised(monkeypatch, "erin")
    _approver(directory, "erin")
    first, first_binding = _park(world)
    second, second_binding = _park(world, agent_says="Please send the other contract")
    assert [r["to"] for r in teams_bot.post_approval(first, bot=bot, world=world)] == ["user:erin-sub"]

    directory.assignments = []  # removed in Entra
    directory.clock.advance(299)
    # Until the kept answer runs out (five minutes by default) the earlier answer stands.
    assert "Approved by" in _message_text(_click(bot, "approve", first, first_binding, who="erin"))
    directory.clock.advance(2)
    refused = _click(bot, "approve", second, second_binding, who="erin", activity_id="later")
    assert "Approved by" not in _message_text(refused) and _status(world, second) == "pending"
    assert "can't open this request" in _message_text(refused) or "can't decide" in _message_text(refused)


def test_when_microsoft_cannot_be_read_the_person_is_refused_and_everyone_else_is_unaffected(
        directory, world, bot, transport, monkeypatch):
    from maverick_dashboard import teams_bot

    _recognised(monkeypatch, "erin")
    _link("alice")
    _approver(directory, "erin")
    directory.script = [("servicePrincipals", httpx.Response(500, text="down"))]
    approval_id, binding = _park(world)
    assert [r["to"] for r in teams_bot.post_approval(approval_id, bot=bot, world=world)] == ["user:alice"]
    refused = _click(bot, "approve", approval_id, binding, who="erin")
    assert "Approved by" not in _message_text(refused) and _status(world, approval_id) == "pending"
    assert "Approved by" in _message_text(_click(bot, "approve", approval_id, binding, activity_id="a"))


# ------------------------------------------------------ other approvers


def test_the_other_approver_rule_sees_approvers_whose_role_comes_only_from_entra(
        directory, env, world, bot, monkeypatch):
    """Alice asked; the only other person who could decide is Entra-only."""
    from maverick.channel_approvals import separate_approver_refusal
    from maverick_dashboard import approval_decisions

    _link("alice")
    _recognised(monkeypatch, "frank")
    approval_id, _binding = _park(world, risk="high", requested_by="user:alice")
    approval = world.get_approval(approval_id)

    assert approval_decisions.other_eligible_approvers(world, approval, "user:alice") == []
    assert separate_approver_refusal(world, approval, "user:alice") == ""  # nobody else: she may

    _approver(directory, "frank")
    directory.clock.advance(400)  # the earlier "nobody" was kept for half a minute
    assert approval_decisions.other_eligible_approvers(world, approval, "user:alice") == ["user:frank-sub"]
    assert "someone else must approve" in separate_approver_refusal(world, approval, "user:alice")


def test_the_other_approver_rule_ignores_directory_people_when_it_is_off_or_unreadable(
        directory, env, world, monkeypatch):
    from maverick_dashboard import approval_decisions

    _recognised(monkeypatch, "frank")
    _approver(directory, "frank")
    approval_id, _binding = _park(world, risk="high", requested_by="user:alice")
    approval = world.get_approval(approval_id)
    directory.script = [("servicePrincipals", httpx.Response(403, json={}))]
    assert approval_decisions.other_eligible_approvers(world, approval, "user:alice") == []
    env.configure(extra=kit.CONFIG.replace("enable = true", "enable = false").replace("{extra}", ""))
    assert approval_decisions.other_eligible_approvers(world, approval, "user:alice") == []


def test_a_person_not_known_to_second_shift_by_any_account_cannot_be_counted(directory, world, monkeypatch):
    """Holding the app role is not enough: there must be a Second Shift user to send the card to."""
    from maverick_dashboard import approval_decisions

    _approver(directory, "frank")  # never signed in, never linked
    approval_id, _binding = _park(world, risk="high", requested_by="user:alice")
    assert approval_decisions.other_eligible_approvers(world, world.get_approval(approval_id), "user:alice") == []


def test_the_role_lookup_for_a_session_less_person_is_what_it_was_when_the_directory_is_off(
        directory, env, monkeypatch):
    from maverick_dashboard import auth

    _recognised(monkeypatch, "erin")
    _approver(directory, "erin", role="SecondShift.Admin")
    env.configure(extra=kit.CONFIG.replace("enable = true", "enable = false").replace("{extra}", ""))
    for who in ("user:alice", "user:carol", "user:erin-sub", "user:nobody"):
        assert auth.role_for_principal(who, directory=True) == auth.role_for_principal(who)
    assert directory.requests == []
    env.configure(extra=kit.CONFIG.replace("{extra}", ""))
    assert auth.role_for_principal("user:erin-sub") == "viewer"  # the default, as before
    assert auth.role_for_principal("user:erin-sub", directory=True) == "admin"


# ------------------------------------------------------------ no secrets


def test_no_token_or_secret_appears_in_logs_cards_or_records(directory, world, bot, transport, monkeypatch, caplog):
    from maverick_dashboard import teams_bot

    _recognised(monkeypatch, "erin")
    _approver(directory, "erin")
    with caplog.at_level(logging.DEBUG):
        approval_id, binding = _park(world)
        teams_bot.post_approval(approval_id, bot=bot, world=world)
        answer = _click(bot, "approve", approval_id, binding, who="erin")
        directory.script = [("servicePrincipals", httpx.Response(401, json={"error": {"message": kit.TOKEN}}))]
        from maverick import entra_directory

        entra_directory.reset_cache()
        entra_directory.role_for_object_id(ERIN)
    approval = world.get_approval(approval_id)
    everything = "\n".join([caplog.text, json.dumps(transport.calls, default=str), _message_text(answer),
                            str(approval.detail), str(approval.decided_by)])
    assert kit.TOKEN not in everything and kit.SECRET not in everything
