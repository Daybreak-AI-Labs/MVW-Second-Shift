"""Explicit one-hop HTTP boundary for first-party integrations.

This complements the process-wide egress guard, which remains necessary for
third-party libraries and for integrations that have not migrated. Callers
must validate initial model-supplied destinations and pin their DNS separately
where needed. This module enforces tenant and enterprise egress policy, and
the redirect helper additionally validates and pins network redirect targets.
"""
from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlsplit

# Whether the requests made inside one paid call may have left this machine:
# ``reported`` once the call used this layer, ``sent`` once a request may have.
_DISPATCH: ContextVar[dict[str, bool] | None] = ContextVar("governed_dispatch", default=None)


def note_dispatch(sent: bool) -> None:
    """Record that a governed request is being made, and whether it may have left."""
    state = _DISPATCH.get()
    if state is not None:
        state["reported"] = True
        state["sent"] = state["sent"] or sent


def never_connected(error: BaseException) -> bool:
    """Whether a request that raised ``error`` never reached the service: no
    connection was made, or the address could not be used."""
    import socket

    if isinstance(error, (ConnectionRefusedError, socket.gaierror)):
        return True
    try:
        import httpx

        return isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout,
                                  httpx.UnsupportedProtocol, httpx.InvalidURL))
    except Exception:  # failure-policy: fail_closed -- cannot tell, so it may have connected
        return False


def send_noting_dispatch(send: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Make one request with ``send``, noting whether it may have left."""
    try:
        response = send(*args, **kwargs)
    except BaseException as error:
        note_dispatch(not never_connected(error))
        raise
    note_dispatch(True)
    return response


def _absolute_http_target(url: Any) -> str:
    """Require the destination whose host will actually be admitted."""
    target = str(url)
    try:
        parsed = urlsplit(target)
        valid_target = parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        valid_target = False
    if not valid_target:
        raise ValueError("governed requests require an absolute HTTP URL")
    return target


def guarded_sender(send: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap an existing HTTP operation while preserving its arguments.

    Acquiring the sender at the call site preserves client configuration and
    test adapters; the policy check always precedes the delegated effect.
    Acquiring it inside :func:`dispatch_tracking` reports whether a request
    left, so a failure before then is known not to have been sent.
    """
    note_dispatch(False)

    def guarded(url: str, *args: Any, **kwargs: Any) -> Any:
        # A bound HTTPX client can enable redirects on the client itself, so
        # the absence of a per-request flag does not imply a one-hop request.
        # Require an explicit False override in that case. Injected senders
        # must themselves honor the same one-hop contract.
        follow_redirects = kwargs.get("follow_redirects")
        owner = getattr(send, "__self__", None)
        if (follow_redirects or kwargs.get("allow_redirects", False)
                or (follow_redirects is not False
                    and getattr(owner, "follow_redirects", False) is True)):
            raise ValueError("governed requests must validate each redirect hop")
        # A relative path can inherit a bound client's base_url after this
        # check. Require an absolute HTTP URL so admission sees the real host.
        target = _absolute_http_target(url)
        from .egress_guard import _check

        _check(target)
        return send_noting_dispatch(send, url, *args, **kwargs)

    return guarded
