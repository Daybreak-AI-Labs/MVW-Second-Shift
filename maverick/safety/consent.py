"""Consent prompts for destructive actions.

Tools that mutate user state (rm, force-push, mass-send, dd, mkfs)
call ``require_consent(action, risk_level)`` which:

  1. Checks the consent ledger -- a previously-granted consent for the
     same (action, scope) returns immediately.
  2. Checks ``MAVERICK_CONSENT_MODE`` env var:
        - "auto-approve" (default) -> grant + log (no friction out of the box)
        - "auto-deny"              -> deny + log
        - "ask"                    -> ask a person: prompt at a terminal; for a
                                      task someone started in Second Shift's chat,
                                      park it on the Approvals page and deny if
                                      nobody decides in time; otherwise (a
                                      headless run) deny at once
        - "dashboard"              -> park in the approvals queue + poll
  3. Logs an audit event for prompt + result.

Threading: prompts serialize through a lock so two parallel agents
don't both pop a prompt simultaneously on the same TTY.

Note: this is the *primitive*. Tools wire it in themselves (the ``shell``
tool does). The base mode is ``auto-approve``, but under **secure-by-default**
**high-** and **critical-risk** actions fail closed to ``ask`` (routing to the
approvals queue / dashboard) instead of auto-approving; low/medium stay
non-interactive out of the box. An operator can widen or narrow this via
``MAVERICK_CONSENT_MODE`` (or per-action config), and ``[security]
secure_defaults = false`` / ``MAVERICK_SECURE_DEFAULT=0`` restores the old
fully-opt-in behavior.
"""
from __future__ import annotations

import math
import os

from ..config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS


def approval_undo_grace_seconds() -> float:
    """How long (seconds) a dashboard decision can still be undone.

    The Approvals page offers "Undo" for this long after approve/reject, so
    the agent-side consumer must not act on a decision until the window has
    passed. ``MAVERICK_APPROVAL_UNDO_GRACE_SECONDS`` wins; otherwise
    ``[approval] undo_grace_seconds`` (Settings > All settings) applies;
    default 30. ``0`` disables undo and restores immediate consumption.
    """
    contract = INTEGER_SETTINGS["approval.undo_grace_seconds"]
    raw = os.environ.get(contract.dashboard_env[0], "")
    if not raw.strip():
        try:
            from ..config import load_config

            value = ((load_config() or {}).get("approval") or {}).get("undo_grace_seconds")
        except Exception:  # config never blocks the approval wait
            value = None
        if isinstance(value, (int, float)) and not isinstance(value, bool) \
                and math.isfinite(value):
            return max(float(contract.minimum), min(float(value), float(contract.maximum)))
        raw = str(contract.default)
    try:
        return max(float(contract.minimum), min(float(raw), float(contract.maximum)))
    except ValueError:
        return float(contract.default)


def approval_requires_acknowledgement() -> bool:
    """Whether approving a high or critical risk request must carry an explicit
    acknowledgement (the Approvals page confirmation; the API's
    ``acknowledged`` field, plus a typed ``confirmation`` for critical risk).

    ``MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT`` wins; otherwise ``[approval]
    require_acknowledgement`` applies; default on.
    """
    contract = BOOLEAN_SETTINGS["approval.require_acknowledgement"]
    raw = os.environ.get(contract.dashboard_env[0], "").strip().lower()
    if raw:
        return raw not in ("0", "false", "no", "off")
    try:
        from ..config import load_config

        value = ((load_config() or {}).get("approval") or {}).get("require_acknowledgement")
    except Exception:  # config never weakens the confirmation
        value = None
    return value if isinstance(value, bool) else contract.default


__all__ = [
]
