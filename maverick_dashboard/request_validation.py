"""Public integration validation errors built from known request fields."""

_FIELDS = frozenset({
    "action", "activity", "approval_id", "binding_sha256", "configuration", "cost_dollars",
    "declared", "department", "detail", "duration_seconds", "goal_id", "idempotency_key",
    "input_tokens", "model_id", "outcome", "output_tokens", "risk", "samples", "steps",
    "summary", "title", "tool", "tool_calls", "tools",
})
_SOURCES = frozenset({"body", "path", "query", "header"})


def fixed_validation_errors(exc) -> list[dict]:
    errors = []
    for error in exc.errors()[:32]:
        loc = error.get("loc", ())
        source = loc[0] if loc and isinstance(loc[0], str) and loc[0] in _SOURCES else "body"
        field = loc[1] if len(loc) >= 2 and isinstance(loc[1], str) and loc[1] in _FIELDS else None
        errors.append({
            "loc": [source, field] if field else [source],
            "msg": "Check this request field." if field else "Check the request format.",
            "type": "value_error",
        })
    return errors
