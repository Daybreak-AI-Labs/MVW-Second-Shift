"""What the in-product service banner says when an AI service is paused,
a connection can't be used, or the database is read-only.

The circuit breaker (:mod:`maverick.circuit_breaker`) pauses an AI provider
after repeated errors (``llm:<provider>`` keys, or ``llm:<provider>:route:<hash>``
for a native client) and lets one test request through once its cooldown ends.
This module turns that state into the three
things a person needs: what is affected, what happens to running tasks, and
when Second Shift checks again. It looks at every provider this workspace uses
(the role models and their backup models), so one healthy backup reads as
"reduced", not "down".

The breaker is held in memory by the process that runs the AI calls. Tasks
run inside the dashboard process by default, so the dashboard sees it;
separate worker processes keep their own and are not reflected here.
"""
from __future__ import annotations
READ_ONLY_TITLE = "Second Shift can't save changes right now because its database is read-only."
READ_ONLY_REFUSAL = (READ_ONLY_TITLE + " Nothing was changed. Everything already saved is safe and can still be "
                     "read; try again once an administrator makes the database writable.")


# Database refusals whose own text is the plain fix (no secrets, no SQL).
_PLAIN_DATABASE_REFUSALS = frozenset({"DatabaseUpgradeNeedsOwner"})


def database_refusal(exc: BaseException | None) -> str:
    """The plain fix for a database refusal anywhere in ``exc``'s chain, else "".

    Every page opens the world model, so one setup problem (a login that does
    not own the tables) failed every page with no reason; the error page and
    readiness detail show the same text ``maverick doctor`` prints.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if type(exc).__name__ in _PLAIN_DATABASE_REFUSALS:
            return str(exc)
        exc = exc.__cause__ or exc.__context__
    return ""


def is_read_only_error(exc: BaseException) -> bool:
    """A write refused because the database or its disk is read-only."""
    text = str(exc).lower()
    return type(exc).__name__ == "OperationalError" and (
        "readonly database" in text or "read-only file system" in text or "read-only database" in text)


__all__ = [
    "READ_ONLY_REFUSAL",
    "READ_ONLY_TITLE",
    "is_read_only_error",
]
