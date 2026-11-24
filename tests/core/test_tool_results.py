"""Shared semantic contract for string-based tool results."""
import copy
import pickle

from maverick.tool_results import ToolOutcome, ToolResultState, classify_tool_result


def test_typed_text_state_survives_copy_and_pickle():
    result = ToolOutcome(ToolResultState.SUCCEEDED, "ERROR is content").as_text()
    for restored in (copy.deepcopy(result), pickle.loads(pickle.dumps(result))):
        assert restored == result
        assert classify_tool_result(restored) is ToolResultState.SUCCEEDED


def test_legacy_outcome_preserves_security_frame_and_state():
    value = '<tool_output trust="untrusted">\nINDETERMINATE: receipt lost\n</tool_output>'
    result = ToolOutcome.from_legacy(value)
    assert result.state is ToolResultState.INDETERMINATE
    assert result.content == value


def test_classifies_reserved_result_states():
    assert classify_tool_result("created") is ToolResultState.SUCCEEDED
    assert classify_tool_result("ERROR: timeout") is ToolResultState.FAILED
    assert classify_tool_result("REFUSED (governed): approval missing") is ToolResultState.REFUSED
    assert classify_tool_result("⚠ BLOCKED by hook") is ToolResultState.REFUSED
    assert classify_tool_result("BLOCKED by Shield") is ToolResultState.REFUSED
    assert classify_tool_result("DRY RUN: would POST /accounts") is ToolResultState.PREVIEW
    assert classify_tool_result("INDETERMINATE: may have committed") is ToolResultState.INDETERMINATE
