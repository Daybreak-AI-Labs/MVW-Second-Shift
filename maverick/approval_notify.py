"""Telling people in Microsoft Teams that an approval is waiting, and that it was decided.

``world_model`` calls :func:`approval_created` once the approval row is saved and
:func:`approval_decided` once its decision has taken effect (on the Approvals
page or in Teams). Both hand the work to a background thread and never raise or
wait: a request is saved whether or not Teams can be reached. With ``[teams]``
off, which is the default, nothing happens.

The settings live here so the kernel can read them without the dashboard:

    [teams]
    enabled = false             # off until an administrator turns it on
    app_id = "..."              # the Azure Bot's Microsoft App ID
    app_secret_env = "TEAMS_BOT_SECRET"   # NAME of the environment variable holding the secret
    tenant_id = "..."           # the organisation's Microsoft Entra tenant id
    allowed_tenants = []        # extra tenants; the bot always accepts tenant_id
    allowed_users = []          # optional: Entra object ids; empty = anyone linked
    channel_id = ""             # optional Teams channel that also gets each card
    service_url = ""            # optional: the Bot Connector address for your Teams cloud

The secret itself is never stored here; ``app_secret_env`` names where it is.
"""
from __future__ import annotations

import logging
import threading

log = logging.getLogger(__name__)

DEFAULT_SECRET_ENV = "TEAMS_BOT_SECRET"  # the NAME of a variable, not a secret  # pragma: allowlist secret


def _text_list(value: object) -> list[str]:
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item).strip().lower() for item in value if str(item).strip()]


def teams_settings() -> dict:
    """The ``[teams]`` table with defaults. An unreadable configuration means
    Teams is off. The secret is read by :func:`teams_secret`, not here."""
    from ._envparse import coerce_bool
    from .config import load_config

    try:
        table = (load_config() or {}).get("teams")
    except Exception:  # noqa: BLE001 -- unreadable settings turn Teams off
        table = None
    table = table if isinstance(table, dict) else {}
    env_name = str(table.get("app_secret_env") or DEFAULT_SECRET_ENV).strip()
    return {
        "enabled": coerce_bool(table.get("enabled"), False),
        "app_id": str(table.get("app_id") or "").strip().lower(),
        "app_secret_env": env_name,
        "tenant_id": str(table.get("tenant_id") or "").strip().lower(),
        "allowed_tenants": _text_list(table.get("allowed_tenants")),
        "allowed_users": _text_list(table.get("allowed_users")),
        "channel_id": str(table.get("channel_id") or "").strip(),
        "service_url": str(table.get("service_url") or "").strip(),
    }


def teams_secret(settings: dict | None = None) -> str:
    """The bot's secret, read from the variable ``app_secret_env`` names (or a
    mounted secret of that name). Empty when it is not set."""
    from .secret_provider import get_secret

    name = (settings or teams_settings())["app_secret_env"]
    try:
        return str(get_secret(name) or "").strip() if name else ""
    except Exception:  # noqa: BLE001 -- an unreadable secret is a missing one
        return ""


def teams_approvals_enabled() -> bool:
    """Whether approvals are announced in Teams: turned on and set up."""
    settings = teams_settings()
    return bool(settings["enabled"] and settings["app_id"] and settings["tenant_id"]
                and teams_secret(settings))


def _spawn(function, *args) -> None:
    threading.Thread(target=function, args=args, daemon=True, name="teams-approval-card").start()


def _run(action: str, approval_id: int, world) -> None:
    try:
        from maverick_dashboard import teams_bot

        getattr(teams_bot, action)(int(approval_id), world=world)
    except Exception as exc:  # noqa: BLE001 -- Teams never changes an approval
        log.warning("teams: %s for approval #%s failed (%s)", action, approval_id, type(exc).__name__)


def approval_created(approval_id: int, *, provenance: str = "", world=None) -> None:
    """Post the new approval's card to the people who may decide it."""
    if not teams_approvals_enabled():
        return
    _spawn(_run, "post_approval", int(approval_id), world)


def approval_reminder(approval_id: int, *, world=None) -> bool:
    """Post a fresh card for a request that is still waiting and running out of
    time, and wait for the answer: True when at least one person or channel got
    it. Never raises."""
    if not teams_approvals_enabled():
        return False
    try:
        from maverick_dashboard import teams_bot

        return any(r.get("ok") for r in teams_bot.post_approval(int(approval_id), world=world))
    except Exception as exc:  # noqa: BLE001 -- a reminder never changes an approval
        log.warning("teams: reminder for approval #%s failed (%s)", approval_id, type(exc).__name__)
        return False


def approval_decided(approval_id: int, *, world=None) -> None:
    """Show the outcome on every card posted for this approval."""
    if not teams_approvals_enabled():
        return
    _spawn(_run, "refresh_approval_cards", int(approval_id), world)
