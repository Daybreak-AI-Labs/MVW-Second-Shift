"""Compare browser request origins and resolve the configured signing audience."""
from __future__ import annotations

import os
from urllib.parse import urlsplit


def configured_public_url() -> str:
    value = (os.environ.get("MAVERICK_PUBLIC_URL") or os.environ.get("SECOND_SHIFT_PUBLIC_URL") or "").strip()
    if value:
        return value
    from maverick.config import config_source_errors, load_global_config

    dashboard = load_global_config().get("dashboard", {})
    if config_source_errors(include_tenant=False) or not isinstance(dashboard, dict):
        raise ValueError("The public origin is unavailable.")
    return str(dashboard.get("public_url") or "").strip()


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        port = parsed.port
        if port == 0:
            return None
        return parsed.scheme, parsed.hostname, port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def signing_origin() -> str | None:
    """Use the installation's configured origin as the signed audience."""
    expected = _origin(configured_public_url())
    if expected is None:
        return None
    scheme, host, port = expected
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        authority += f":{port}"
    return f"{scheme}://{authority}"


def same_origin(request) -> bool:
    """Use the public origin behind a proxy and require an origin on writes."""
    try:
        expected = _origin(configured_public_url() or str(request.base_url))
    except (OSError, TypeError, ValueError):
        return False
    supplied = request.headers.get("origin") or request.headers.get("referer")
    return bool(expected and supplied and expected == _origin(supplied))
