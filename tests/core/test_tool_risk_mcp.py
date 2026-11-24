"""MCP tools fail safe to ``high`` risk by default.

An unclassified ``mcp_*`` tool runs arbitrary code through a third-party
server, so -- unlike a generic unclassified tool, which stays ``medium`` --
it defaults to ``high``. A ``[security.tool_risk]`` override is still checked
first, so a trusted MCP server can be relaxed deliberately. This closes the
gap where a `max_risk="medium"` ceiling / governance gate silently admitted
arbitrary MCP tools.
"""
from __future__ import annotations

import importlib


def _write_config(tmp_path, body: str = "") -> None:
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.toml").write_text(body)
    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)


def test_unclassified_mcp_tool_defaults_high(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path)  # no overrides
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("mcp_github__create_issue") == "high"
    assert tool_risk("mcp_anything__do") == "high"


def test_non_mcp_unknown_stays_medium(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path)
    from maverick.safety.tool_risk import tool_risk, tool_risk_is_classified
    # Every unrated name now fails safe to high, but only the `mcp_` *prefix*
    # counts as a deliberate classification (a name that merely contains
    # "mcp" is just unrated).
    assert tool_risk("some_unknown_tool") == "high"
    assert tool_risk("not_mcp_really") == "high"
    assert tool_risk_is_classified("mcp_github__create_issue") is True
    assert tool_risk_is_classified("not_mcp_really") is False


def test_builtin_classifications_unaffected(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path)
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("shell") == "high"
    assert tool_risk("read_file") == "low"


def test_config_override_relaxes_mcp(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '\n'.join([
        "[security.tool_risk]",
        '"mcp_*" = "medium"',
        '"mcp_trusted__read" = "low"',
    ]))
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("mcp_other__write") == "medium"   # glob relaxation wins
    assert tool_risk("mcp_trusted__read") == "low"     # exact override wins
