"""Re-verification of an explicit API-key bearer before a permission check.

This product accepts no API keys, so there is never a key to re-verify.
"""
from __future__ import annotations


def refresh_explicit_api_key(request) -> None:
    return None


__all__ = [
    "refresh_explicit_api_key",
]
