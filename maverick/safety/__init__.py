"""Safety utilities for Second Shift.

Currently:
  - ``secret_detector``: regex-based credential scrubbing for tool outputs.
  - ``consent``: prompt the user before destructive actions; ledger
    of granted approvals.
  - ``tool_acl``: allow-list / deny-list filtering of registered tools.

This package is intentionally lightweight (no fancy ML deps). Heavier
classifiers live behind optional extras and are loaded on demand.
"""

__all__ = [
]
