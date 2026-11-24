"""Controls behind the /trust page that were only reachable from the CLI.

* ``GET  /api/v1/trust/pubkey`` -- this installation's public security key to
  share with partners (``maverick trust pubkey``).
* ``POST /api/v1/trust/enforcement`` -- turn blocking of unlisted outside
  agents on or off (``[agent_trust] enforce``), administrators only.
* ``POST /api/v1/trust/agents/{id}/check`` -- replay the access decision for
  one agent without changing anything (``maverick trust verify``).
* ``PUT  /api/v1/trust/agents/{id}`` -- change an app-managed agent's limits
  while keeping its connection tokens, expiry and block state (re-registering
  would drop them).

* ``POST /api/v1/trust/federation/{peer}/limit`` -- raise a federation
  peer's request limit or start its count again, installation administrators
  only, in the installation's own tenant where the federation server admits
  requests (``maverick trust admission-limit``).
* ``POST /api/v1/trust/federation/limits/storage`` -- raise how many partner
  requests the workspace keeps before refusing every peer (``--storage``).
* ``POST /api/v1/trust/federation/limits/start-over`` -- set an unreadable
  limits file aside so the default limits apply (``--start-over``).

Restoring a blocked agent (``maverick trust unrevoke``) already has an API.
Each change runs one shared function, which Copilot also calls
(``product_operations_agent_trust`` and ``product_operations_partner_limits``).
"""
from __future__ import annotations

from fastapi import HTTPException, Request

from . import auth
from .auth import require_permission


_UNSAVED = "The list of outside agents could not be saved. Nothing was changed."


def _not_recorded() -> HTTPException:
    return HTTPException(status_code=503, detail=_UNRECORDED)


def _not_saved() -> HTTPException:
    # The audit row may already be written: like the partner limits, the
    # record comes first, so a failed save leaves a record of the attempt.
    return HTTPException(status_code=503, detail=_UNSAVED)


class _NotSaved(Exception):
    """The registry file could not be written (kept apart from a failure of
    the containment authority around an unblock)."""


def set_agent_blocked(request: Request, agent_id: str, blocked: bool) -> None:
    """Block or unblock an app-managed agent (same checks as
    :func:`register_agent`). Unblocking is refused while security has
    contained the agent."""
    require_permission(request, "admin")
    from maverick import agent_trust
    from maverick.audit import AuditRefused
    from maverick.revocation import ProtectedRevocationError, shared

    actor = _actor(request)

    def flip(revoked: bool) -> bool:
        try:
            return agent_trust.set_revoked(agent_id, revoked, actor=actor)
        except OSError as exc:
            raise _NotSaved from exc

    try:
        changed = (
            flip(True)
            if blocked
            else shared().run_if_unprotected(f"agent:{agent_id}", lambda: flip(False))
        )
    except (AuditRefused, agent_trust.ChangeNotRecorded) as exc:
        raise _not_recorded() from exc
    except _NotSaved as exc:
        raise _not_saved() from exc
    except ProtectedRevocationError as exc:
        raise HTTPException(
            status_code=409,
            detail="agent is security-contained; use the control-plane release",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="containment authority is unavailable; restore refused",
        ) from exc
    if not changed:
        raise HTTPException(
            status_code=404,
            detail="this agent is defined in the server's config file, not in "
            "the app-managed registry. Register the same id here to "
            "override it, or ask your administrator to edit the config.",
        )
_UNRECORDED = "The change could not be recorded, so it was not made."


def _actor(request: Request) -> str:
    return str(auth.caller_principal(request) or "authorized-local-operator")
