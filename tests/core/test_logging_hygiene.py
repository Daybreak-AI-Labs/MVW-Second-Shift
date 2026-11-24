"""Observability and logging hygiene.

  - JSON formatter must not ship caller-attached `extra=` secrets verbatim:
    redact secret-named keys, scrub inline secrets in string values.
  - goal-context contextvars must reset to the PRIOR value (token-based), so
    concurrent/nested goals don't mislabel each other's log lines.
  - health.doctor must report a real provider outage (connection/timeout/5xx)
    as RED, not a benign YELLOW "validation skipped".
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from maverick.logging_config import JsonFormatter


def _fmt(**extra):
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None)
    for k, v in extra.items():
        setattr(rec, k, v)
    return json.loads(JsonFormatter().format(rec))


def test_secret_named_key_redacted():
    out = _fmt(api_key="sk-ant-abcdefghij1234567890XYZ", count=42)
    assert out["api_key"] == "[REDACTED]"
    assert out["count"] == 42  # benign field preserved


def test_various_secret_named_keys_redacted():
    out = _fmt(password="hunter2", auth_header="Bearer xyz", session_token="s",
               SECRET="x", normal_field="ok")
    for k in ("password", "auth_header", "session_token", "SECRET"):
        assert out[k] == "[REDACTED]", k
    assert out["normal_field"] == "ok"


def test_inline_secret_in_value_scrubbed():
    # Even a benign-named key gets its value scrubbed for inline secrets.
    out = _fmt(note="key is sk-ant-abcdefghij1234567890XYZ ok")
    assert "sk-ant-abcdefghij" not in out["note"]
    assert "[REDACTED" in out["note"]


def test_benign_values_untouched():
    out = _fmt(url="https://example.com/path", n=3, flag=True)
    assert out["url"] == "https://example.com/path"  # 'url' not treated as secret
    assert out["n"] == 3 and out["flag"] is True


def test_nested_secret_in_extra_value_is_scrubbed():
    # A secret buried in a dict/list extra (not a top-level string) must not
    # slip past just because the value isn't a string.
    out = _fmt(meta={"inner": {"note": "key sk-ant-abcdefghij1234567890XYZ x"}},
               items=["clean", "tok sk-ant-abcdefghij1234567890XYZ"])
    body = json.dumps(out)
    assert "sk-ant-abcdefghij" not in body
    assert out["meta"]["inner"]["note"].count("[REDACTED") == 1
    assert out["items"][0] == "clean"  # structure + benign values preserved


def test_secret_named_key_redacted_at_any_depth():
    out = _fmt(payload={"ok": 1, "auth_token": "whatever", "sub": {"password": "p"}})
    assert out["payload"]["auth_token"] == "[REDACTED]"
    assert out["payload"]["sub"]["password"] == "[REDACTED]"
    assert out["payload"]["ok"] == 1


def test_message_interpolated_secret_is_scrubbed():
    # logger.info("resp %s", body) where body carries a key: getMessage()
    # interpolates it into msg, which must be scrubbed like the extras are.
    rec = logging.LogRecord(
        "t", logging.INFO, __file__, 1,
        "resp %s", ("key=sk-ant-abcdefghij1234567890XYZ",), None)
    out = json.loads(JsonFormatter().format(rec))
    assert "sk-ant-abcdefghij" not in out["msg"]
    assert "[REDACTED" in out["msg"]


def test_exception_traceback_is_scrubbed():
    # A provider exception's message routinely embeds the API key; the formatted
    # traceback must be scrubbed, not shipped verbatim.
    try:
        raise RuntimeError("provider rejected key sk-ant-abcdefghij1234567890XYZ")
    except RuntimeError:
        import sys
        rec = logging.LogRecord("t", logging.ERROR, __file__, 1,
                                "boom", None, sys.exc_info())
    out = json.loads(JsonFormatter().format(rec))
    assert "sk-ant-abcdefghij" not in out["exc"]
    assert "[REDACTED" in out["exc"]


def test_anonymous_mode_anonymizes_json_log_record(monkeypatch):
    monkeypatch.setenv("MAVERICK_ANON", "1")
    home_path = str(Path.home() / "case_notes.txt")

    out = _fmt(
        user_id="user-123",
        channel="slack-C123",
        title="Jane Patient diabetes plan",
        msg="contact jane.patient@example.com at 415-555-1212 from " + home_path,
        path=home_path,
    )
    body = json.dumps(out)
    assert "user-123" not in body
    assert "slack-C123" not in body
    assert "Jane Patient" not in body
    assert "jane.patient@example.com" not in body
    assert "415-555-1212" not in body
    assert home_path not in body
    assert out["user_id"].startswith("user_id#")
    assert out["channel"].startswith("channel#")
    assert out["path"] == "case_notes.txt"
