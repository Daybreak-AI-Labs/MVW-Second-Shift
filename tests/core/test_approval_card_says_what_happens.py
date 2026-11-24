"""An approval card says what will happen, in words a person can check.

The exact command a shell step will run is bound into its card, so the person
allowed to read the card sees it (with any secret masked); fingerprints stay
technical detail; the spending line is a sentence, never a raw mapping; and
the text sent to shared chat rooms and the daily summary stays content-minimal
-- it points to the Approvals page instead of carrying the command.
"""
from __future__ import annotations

import time

import pytest

from maverick.approval_cards import ApprovalCardError, build_approval_card, validate_approval_card

COMMAND = "mkdir -p archive && echo moved > archive/README.txt"
SHELL_BUDGET = {
    "runtime": {"currency": "USD", "external_effect_cost": "unmeasured",
                "authority_sha256": "5ac93412c16f5f3723303a3784b956b2cd9fe81eafd414a6adbc660b6595a5c0"},  # pragma: allowlist secret
    "operation": {"timeout_seconds": None},
}


def _card(**overrides):
    values = dict(
        action="shell", summary="Run a command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": COMMAND},
        parameter_summary=["Runs this exact command once; nothing else is approved."],
        actor="user:sam", workspace="local", role="operator", authority_versions={},
        input_versions={}, credential_versions={}, budget=SHELL_BUDGET,
        expires_at=time.time() + 300, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    values.update(overrides)
    return build_approval_card(**values)


def test_the_exact_command_is_bound_into_the_card():
    card = _card(display_command=COMMAND)
    assert card["display"] == {"command": COMMAND}
    assert validate_approval_card(card)["display"]["command"] == COMMAND
    tampered = dict(card, display={"command": "rm -rf /"})
    with pytest.raises(ApprovalCardError):
        validate_approval_card(tampered)


def test_multi_line_commands_keep_their_lines():
    script = "cd archive\nls -la\n"
    assert _card(display_command=script)["display"]["command"] == script


def test_a_secret_in_the_command_is_masked_on_the_card():
    secret = "sk-ant-api03-" + "A" * 80  # pragma: allowlist secret
    card = _card(display_command=f"curl -H 'x-api-key: {secret}' https://example.test")
    assert secret not in card["display"]["command"]
    assert "REDACTED" in card["display"]["command"]
    validate_approval_card(card)


def test_cards_without_a_command_still_validate_and_unknown_fields_do_not():
    validate_approval_card(_card())
    card = _card(display_command=COMMAND)
    widened = dict(card, display={"command": COMMAND, "note": "x"})
    with pytest.raises(ApprovalCardError):
        validate_approval_card(widened)
    with pytest.raises(ApprovalCardError):
        _card(display_command="x" * 5000)
