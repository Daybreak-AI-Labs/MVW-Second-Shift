"""Current installation limits for existing signed browser sessions."""
from __future__ import annotations

from maverick.config import get_auth_sessions


def company_ttl() -> int:
    return get_auth_sessions()["company_hours"] * 3600


def effective_end(*, expires_at: float, issued_at: float, last_seen: float,
                  via: str) -> float:
    settings = get_auth_sessions()
    ends = expires_at
    if via == "session" and settings["company_hours"]:
        ends = min(ends, issued_at + settings["company_hours"] * 3600)
    if settings["idle_minutes"]:
        ends = min(ends, last_seen + settings["idle_minutes"] * 60)
    return ends


def idle_minutes() -> int:
    return get_auth_sessions()["idle_minutes"]
