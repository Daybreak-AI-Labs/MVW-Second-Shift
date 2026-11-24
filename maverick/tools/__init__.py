"""Tool registry. Sync + async tools; same interface.

Each tool is a name + JSON schema + executor function. The executor may be a
sync function returning str, or an async coroutine returning str.

``base_registry`` accepts an optional list of MCPClient
instances. If provided, every tool the MCP servers expose is
registered as ``mcp_<server>__<tool>`` and routed through the
MCPClient. This is how Second Shift consumes the wider MCP ecosystem.
"""
from __future__ import annotations

# Role-specific additions to CORE_TOOL_NAMES under [tools] exposure = "core".
# Kept small: everything else stays discoverable through find_tools. A role
# without an entry (worker, writer, summarizer, verifier, a pack's name...)
# gets exactly CORE_TOOL_NAMES.
ROLE_TOOL_OVERLAYS: dict[str, frozenset[str]] = {
    "orchestrator": frozenset({"task_graph", "spend_report"}),
    "coder": frozenset({
        "git_advanced", "test_impact", "test_gen", "semantic_code_search",
        "lsp_bridge", "cross_repo_deps",
    }),
    "researcher": frozenset({
        "arxiv", "wikipedia", "semantic_scholar", "hackernews",
        "citation_verifier", "web_archive", "spreadsheet",
    }),
    "analyst": frozenset({"pandas_query", "spreadsheet", "sql_query", "format_money", "currency"}),
    "writer": frozenset({"outline_writer", "plain_language", "pandoc", "latex"}),
}
ROLE_TOOL_OVERLAYS["coding"] = ROLE_TOOL_OVERLAYS["coder"]
ROLE_TOOL_OVERLAYS["reviewer"] = ROLE_TOOL_OVERLAYS["coder"]
ROLE_TOOL_OVERLAYS["revisor"] = ROLE_TOOL_OVERLAYS["coder"]
