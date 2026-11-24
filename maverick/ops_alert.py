"""Operational alerts — page an operator on INFRASTRUCTURE events (killswitch
trip, budget exhaustion, audit-chain break, ...), distinct from the agent-task
deliverable notifications.

Every existing notification/webhook seam is wired to agent-task lifecycle
events; nothing paged an SRE when the killswitch tripped or a budget cap blew.
This is that seam: a single :func:`alert` entry point that, when enabled, routes
an operational event through the operator's existing notification transport
(:func:`maverick.notifications.notify`) at high priority.

**Off by default** (outward-facing). Enable with ``[alerts] enabled = true`` /
``MAVERICK_ALERTS=1``. When disabled — or if delivery fails — :func:`alert` is a
strict, non-raising no-op so it can be called from anywhere (including the
killswitch and the budget guard) without ever breaking the path it observes.

An alert goes to every channel named in ``[alerts] backends`` (``teams``,
``email``), or to the single ``[notifications] backend`` when that list is not
set. :func:`alert` waits for those channels to answer, each within its own
time limit, and returns True only when at least one accepted the message.
:func:`send_test` sends a test message the same way and says, per channel,
what happened; :func:`delivery_status` reports how delivery is set up.

It does not retry, batch or schedule: one call is one attempt per channel.
Nothing it returns or logs holds a webhook address or a password.
"""
from __future__ import annotations

import logging
import os

from ._envparse import coerce_bool, is_truthy

log = logging.getLogger(__name__)

# Map a severity to the notification priority understood by notifications.notify.
_PRIORITY = {"critical": "max", "high": "high", "warning": "default", "info": "low"}

_TEST_TITLE = "Second Shift test alert"
_TEST_BODY = ("This is a test. If you can read it, alerts from Second Shift reach this channel. "
              "Nothing needs to be done.")
_NOT_A_CHANNEL = "Not sent: this is not a supported alert channel. Use teams or email."
_NOT_STARTED = "The test was not sent: the delivery history or the settings could not be read."
# What a test says about a channel when the delivery history holds no reason.
_WITHOUT_A_REASON = {
    "failed": "Not sent. Check this channel's settings.",
    "unknown": "Delivery could not be confirmed. Check the channel before sending again.",
}


def alerts_enabled() -> bool:
    """Operational alerting is opt-in. ``MAVERICK_ALERTS`` env wins over
    ``[alerts] enabled``; off by default."""
    env = os.environ.get("MAVERICK_ALERTS")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    try:
        from .config import load_config
        return coerce_bool(((load_config() or {}).get("alerts") or {}).get("enabled"))
    except Exception:  # pragma: no cover - config never blocks an alert path
        return False


def _configured_names() -> list[str]:
    """The channel names alerts are set to use, in order and without repeats:
    ``[alerts] backends`` when it names any, else the single
    ``[notifications] backend``. Lower-cased; ``none`` and anything that is
    not a plain name are left out."""
    from .config import load_config
    from .notifications import _requested

    cfg = load_config() or {}
    alerts = cfg.get("alerts") if isinstance(cfg.get("alerts"), dict) else {}
    section = cfg.get("notifications") if isinstance(cfg.get("notifications"), dict) else {}
    named = alerts.get("backends")
    if isinstance(named, str):  # one name, not its letters
        named = [named]
    named = list(named) if isinstance(named, (list, tuple)) else None
    return list(dict.fromkeys(_requested(section, named)))


def _channels() -> tuple[list[str], list[str]]:
    """``(used, ignored)``: the channels alerts go to, and the configured names
    that are not a channel (a removed one such as ``slack``, or a typo)."""
    from .notifications import BACKENDS

    names = _configured_names()
    return [n for n in names if n in BACKENDS], [n for n in names if n not in BACKENDS]


def alert(event: str, detail: str = "", *, severity: str = "high") -> bool:
    """Page the operator about an operational ``event`` on every alert
    channel. Returns True only when at least one channel accepted the message;
    False when alerting is disabled, no channel is set up or every channel
    failed. Waits for each channel, up to its time limit, and never raises
    — the caller is always on a hot/critical path it must not break."""
    if not alerts_enabled():
        return False
    try:
        from .notifications import notify
        used, ignored = _channels()
        if ignored:
            log.warning("ops alert: %s is not an alert channel and is ignored (use teams or email)",
                        ", ".join(ignored))
        if not used:
            log.warning("ops alert %r was not sent: alerts are on but no alert channel is set up", event)
        fired = notify(
            detail or event,
            title=f"Second Shift ALERT: {event}",
            priority=_PRIORITY.get(severity, "high"),
            category="ops_alert",
            # An empty list would fall back to the notification default, so
            # "no alert channel" is said outright.
            backends=used or ["none"],
            async_dispatch=False,
            batch=False,
        )
        return fired > 0
    except Exception as e:  # pragma: no cover - alerting must never crash a path
        log.warning("ops alert delivery failed for %r: %s", event, type(e).__name__)
        return False


def _test_messages(request_id: str) -> dict[str, str]:
    """What the delivery history recorded for one test, by channel. Empty when
    the history is turned off or cannot be read."""
    try:
        from .notification_receipts import DeliveryReceipts

        return {row["backend"]: row["message"] for row in DeliveryReceipts().recent()
                if row.get("request_id") == request_id}
    except Exception:  # noqa: BLE001 -- the fixed wording stands in for a history that cannot be read
        return {}


def send_test() -> dict[str, str]:
    """Send one test message to every alert channel now and report, per
    channel, ``sent`` or the plain reason it was not. It runs whether or not
    alerts are on, so delivery can be proven before they are switched on, and
    it is kept in the delivery history as a test. Never raises; no result
    holds a webhook address, a password or any other credential."""
    import uuid

    try:
        used, ignored = _channels()
    except Exception as e:  # noqa: BLE001 -- a delivery test never raises
        log.warning("ops alert test failed: %s", type(e).__name__)
        return {}
    results = dict.fromkeys(ignored, _NOT_A_CHANNEL)
    if not used:
        return results
    request_id = str(uuid.uuid4())
    states: list[str] = []
    try:
        from .notifications import notify

        notify(_TEST_BODY, title=_TEST_TITLE, priority="high", category="ops_alert_test",
               backends=used, async_dispatch=False, batch=False,
               delivery_key=request_id, delivery_kind="test", outcomes=states)
    except Exception as e:  # noqa: BLE001 -- a delivery test never raises
        log.warning("ops alert test failed: %s", type(e).__name__)
        return {**results, **dict.fromkeys(used, _NOT_STARTED)}
    reached = dict(zip(used, states, strict=False))
    messages = _test_messages(request_id)
    for name in used:
        state = reached.get(name, "unknown")
        results[name] = "sent" if state == "delivered" else (
            messages.get(name) or _WITHOUT_A_REASON.get(state, _WITHOUT_A_REASON["unknown"]))
    return results


def delivery_status() -> dict:
    """How alert delivery is set up, for an administrator's page: whether
    alerts are on, each channel they go to and whether it is ready (with the
    plain reason when it is not), and the configured names that are not
    channels. A webhook address is reported only as set or not set."""
    from .notifications import BACKENDS, backend_status

    used, ignored = _channels()
    return {
        "enabled": alerts_enabled(),
        "channels": [backend_status(name) for name in used],
        "ignored": ignored,
        "available": list(BACKENDS),
    }


__all__ = [
    "alert",
    "alerts_enabled",
]
