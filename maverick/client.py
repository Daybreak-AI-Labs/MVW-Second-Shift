"""Client binding — one Second Shift deployment, exactly one enterprise client.

Second Shift is deployed **one instance per enterprise client** (never a shared,
hosted multi-tenant service). This module makes that binding explicit and
**fail-closed** so client data can never land in an ambiguous, un-scoped
location:

* the deployment declares its client via ``[client] id`` or
  ``MAVERICK_CLIENT_ID``;
* that id becomes the tenant **floor** (consumed by
  :func:`maverick.paths.current_tenant_id`), so every data path — world DB,
  audit chain + keys, cross-session memory, fleet memory — resolves under
  ``~/.maverick/tenants/<client>/...`` instead of a shared root. There is no
  un-scoped global location for operating client data to accumulate in. Minimal
  signed offboarding receipts intentionally survive outside an erased root;
* in **enforced** mode (``[client] enforce = true``, ``MAVERICK_CLIENT_ENFORCE``,
  or enterprise mode) a missing/invalid client id REFUSES to start — there is no
  silent fallback to the shared root.

Off by default (no client id configured) => legacy single-root behaviour,
byte-for-byte unchanged, so existing single-tenant installs are unaffected.

The client id is immutable for a deployment's lifetime, so it is resolved once
and cached; set ``MAVERICK_CLIENT_ID`` in the service unit / image so the hot
path (every ``data_dir`` call resolves the tenant floor) never parses config.
"""
from __future__ import annotations

import logging
import os
import re

from ._envparse import coerce_bool, is_truthy

log = logging.getLogger(__name__)

# A client id becomes the tenant path segment, so it must satisfy the tenant
# charset (paths._SAFE_TENANT_CHARS): digits/._- and LOWERCASE letters only.
# Lowercase is required because the id is a directory name: on a case-insensitive
# filesystem (macOS APFS, Windows NTFS) "Acme" and "acme" resolve to the SAME
# directory, so allowing mixed case would let two distinct client ids collide
# onto one data root — the one thing the per-client binding must prevent.
_CLIENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Resolved once per process (the binding is immutable for a deployment). Tests
# reset via reset_client_cache().
_UNSET = object()
_cached: object = _UNSET
_strict_cached: object = _UNSET


class ClientBindingError(RuntimeError):
    """Raised when a client-bound deployment is started without a valid client id."""


def reset_client_cache() -> None:
    """Forget the cached client id (test hook; the id is immutable in prod)."""
    global _cached, _strict_cached
    _cached = _UNSET
    _strict_cached = _UNSET


def _raw_client_id() -> str:
    """The configured client id, unvalidated. ``MAVERICK_CLIENT_ID`` wins over
    ``[client] id``; empty string when neither is set."""
    raw = (os.environ.get("MAVERICK_CLIENT_ID") or "").strip()
    if not raw:
        try:
            from .config import config_source_errors, load_config

            cfg = load_config()
            if config_source_errors():
                raise ClientBindingError(
                    "client binding unavailable: an active config source is invalid"
                )
            client = cfg.get("client") or {}
            if not isinstance(client, dict):
                raise ClientBindingError("[client] must be a table")
            raw = str(client.get("id") or "").strip()
        except ClientBindingError:
            raise
        except Exception as exc:
            raise ClientBindingError(f"client binding unavailable: {exc}") from exc
    return raw


def _resolve() -> str | None:
    try:
        raw = _raw_client_id()
    except ClientBindingError:
        # Resilient on the hot path: a corrupt/unreadable config source must not
        # crash an explicitly diagnostic-only binding lookup or a command like
        # ``maverick config-lint`` whose whole job is to REPORT that corrupt
        # file. Production still fails closed at the startup guard
        # ``require_client_binding()``, which calls ``_raw_client_id()``
        # directly, and every trust/auth caller inspects ``config_source_errors``
        # itself -- so the fail-closed seam is preserved where it belongs.
        return None
    if not raw:
        return None
    if not _CLIENT_RE.fullmatch(raw):
        # Diagnostic resolution reports an invalid id as unbound. Storage path
        # resolution uses strict_client_id() and therefore still fails closed.
        log.warning("[client] id %r is invalid (want %s); ignoring it",
                    raw, _CLIENT_RE.pattern)
        return None
    return raw


def client_id() -> str | None:
    """The deployment's bound client id, or ``None`` (legacy shared root).

    ``MAVERICK_CLIENT_ID`` wins over ``[client] id``. Cached for the process.
    """
    global _cached
    if _cached is _UNSET:
        _cached = _resolve()
    return _cached  # type: ignore[return-value]


def strict_client_id() -> str | None:
    """Resolve the binding without turning errors into unbound legacy mode.

    ``client_id()`` intentionally remains resilient for diagnostics and path
    display. A database predicate is a security boundary, however, so corrupt
    or invalid configured identity must raise instead of becoming ``None``.
    """
    global _cached, _strict_cached
    if _strict_cached is not _UNSET:
        return _strict_cached  # type: ignore[return-value]
    if _cached is not _UNSET and _cached is not None:
        _strict_cached = _cached
        return _cached  # type: ignore[return-value]
    raw = _raw_client_id()
    if not raw:
        _strict_cached = None
        return None
    if not _CLIENT_RE.fullmatch(raw):
        raise ClientBindingError(
            f"[client] id {raw!r} is invalid: must match {_CLIENT_RE.pattern} "
            "(lowercase letters, digits, '.', '_', '-'; lowercase is required so "
            "the data directory can't collide with a differently-cased id on a "
            "case-insensitive filesystem). Refusing to continue unscoped."
        )
    _cached = raw
    _strict_cached = raw
    return raw


def client_binding_enforced() -> bool:
    """Is a client binding REQUIRED to operate?

    On via ``MAVERICK_CLIENT_ENFORCE``, ``[client] enforce = true``, or
    enterprise mode (a deployment handling a real client's sensitive data must
    be provably bound to that client). Off by default. One decision reads the
    configuration once (``config.single_read``)."""
    from .config import single_read

    with single_read():
        return _client_binding_enforced()


def _client_binding_enforced() -> bool:
    env = os.environ.get("MAVERICK_CLIENT_ENFORCE")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            return True
    except Exception:  # pragma: no cover
        pass
    try:
        from .config import load_config
        return coerce_bool(((load_config() or {}).get("client") or {}).get("enforce"))
    except Exception:
        return False


__all__ = [
    "ClientBindingError",
    "client_id",
    "strict_client_id",
    "client_binding_enforced",
    "reset_client_cache",
]
