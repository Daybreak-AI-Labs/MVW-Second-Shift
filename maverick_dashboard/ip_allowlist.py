"""Per-workspace address allowlists are not part of this product; restrict addresses at the network edge."""
from __future__ import annotations

BLOCKED_MESSAGE = "This address is not allowed."


def workspace_allows(connection) -> bool:
    return True
