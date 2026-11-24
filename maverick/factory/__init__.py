"""The agent factory: describe an agent, draft it with a model, test it, get it approved, release it.

The factory uses the Second Shift runtime (``second_shift_runtime``) as a library for the one agent
definition format, the model clients and test runs. The runtime is an optional install: without it the
factory pages say so plainly and the rest of Second Shift works as before.

A released version can be exported as a package for Azure, AWS Bedrock AgentCore or Microsoft Foundry (``export``), and
pushed to Foundry when an administrator allows it (``foundry_push``).
"""
from __future__ import annotations

NOT_INSTALLED = (
    "The agent factory is not installed on this server. An administrator can add it with "
    "pip install 'second-shift[factory]' (or install the second-shift-runtime package); "
    "everything else in Second Shift works without it."
)


class FactoryError(Exception):
    """Something the person can fix. The message is plain and safe to show."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def runtime_available() -> bool:
    try:
        import second_shift_runtime  # noqa: F401
    except ImportError:
        return False
    return True
