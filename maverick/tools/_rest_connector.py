"""Generic authenticated-REST connector factory.

Most enterprise SaaS exposes a token-authed JSON REST API with the same shape:
a base URL, a bearer/basic/custom-header token, GET to read, POST/PUT/PATCH/
DELETE to write. ``make_rest_tool`` turns that shape into a Second Shift ``Tool``
so the long tail of connectors is a one-line spec instead of a hand-written
module — while keeping the house rules: explicit-env auth (no ambient creds),
``confirm=true`` gating on every write, ``ERROR:``-prefixed failures, and a
lazy ``httpx`` import.

The agent supplies the API ``path`` (the description carries the base URL +
auth env + a couple of example paths), so one factory covers every endpoint of
a service without hard-coding entities.
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

from ..connector_attempts import CONTROL_ERRORS

_ENV_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_RESPONSE_LIMIT = 4000


class _ConnectorConfigError(RuntimeError):
    """A configuration failure whose public detail is safe to return.

    Arbitrary ``RuntimeError`` text at the connector boundary may contain an
    active credential reflected by an HTTP client or provider.  This narrower
    type carries only validated environment-variable identifiers or one of the
    fixed policy explanations below, so operators keep actionable remediation
    without reopening that value-disclosure path.
    """

    def __init__(self, *env_names: str, reason: str = "missing"):
        if reason == "scoped_connection":
            message = (
                "connector requires a principal-authorized saved connection in "
                "authenticated enterprise execution; ambient environment "
                "credentials are not permitted"
            )
        elif reason == "ambient_extra_header":
            message = (
                "ambient extra-header credentials are unavailable in "
                "authenticated enterprise execution"
            )
        elif (
            reason == "missing"
            and env_names
            and len(env_names) <= 4
            and all(
                isinstance(name, str) and _ENV_IDENTIFIER.fullmatch(name)
                for name in env_names
            )
        ):
            message = f"connector requires {' + '.join(env_names)}"
        else:
            # Never reflect an invalid/developer-controlled identifier.
            message = "connector configuration is incomplete"
        super().__init__(message)


def _capability_egress_denial(url: str, args: dict[str, Any], *, name: str) -> str | None:
    """Apply an active capability host scope to REST connector base URLs."""
    raw_allow_hosts = args.get("_capability_allow_hosts") if isinstance(args, dict) else None
    if not raw_allow_hosts:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        host = None
    if not host:
        return None
    host_l = host.lower().rstrip(".")
    for pat in raw_allow_hosts:
        pat_l = str(pat).lower().rstrip(".")
        if fnmatch.fnmatchcase(host_l, pat_l):
            return None
    return f"capability policy denies host {host!r} for tool {name!r}"


def _connection_fallback(name: str) -> tuple[str, str] | None:
    """An authorized dashboard-created credential for ``name``, if present.

    Standard/local calls use this as an env fallback. Authenticated enterprise
    calls require it and never borrow ambient process credentials.
    """
    try:
        from maverick import connections
        return connections.resolve(name)
    except Exception:  # pragma: no cover -- a connection read never breaks a tool
        return None


def _requires_scoped_connection() -> bool:
    """Whether ambient process credentials are forbidden for this request."""
    try:
        from maverick import connections
        from maverick.enterprise import enterprise_enabled

        from ..template_connections import active
        return active() or bool(enterprise_enabled() and connections.current_principal())
    except Exception:  # pragma: no cover -- an unknown policy forbids ambient credentials
        return True


def _credential_config(
    name: str,
    base_url_env: str,
    token_env: str,
    *,
    default_base_url: str = "",
) -> tuple[str, str]:
    """Resolve a credential without crossing principal authorization scopes.

    Standard/operator execution retains the legacy per-field env precedence.
    Authenticated enterprise execution may use only a saved connection that
    admits the current principal; operator-global env credentials are ambient
    authority and therefore unavailable to tenant users and agents.
    """
    conn = _connection_fallback(name)
    if _requires_scoped_connection():
        base = (str(conn[0]).strip().rstrip("/") if conn else "") or default_base_url
        tok = str(conn[1]).strip() if conn else ""
        if not base or not tok:
            raise _ConnectorConfigError(reason="scoped_connection")
        return base, tok

    base = (
        os.environ.get(base_url_env, "").strip().rstrip("/")
        or default_base_url
    )
    tok = os.environ.get(token_env, "").strip()
    if (not base or not tok) and conn:
        base = base or str(conn[0]).rstrip("/")
        tok = tok or conn[1]
    if not base or not tok:
        missing = tuple(
            env_name
            for value, env_name in ((base, base_url_env), (tok, token_env))
            if not value
        )
        raise _ConnectorConfigError(*missing)
    return base, tok


def _env_config(name: str, base_url_env: str, token_env: str) -> tuple[str, str]:
    """Resolve ``(base_url, token)`` under the active credential policy."""
    return _credential_config(name, base_url_env, token_env)


def _build_auth_headers(
    tok: str, *, basic: bool, token_header: str, scheme: str,
    extra_headers_env: dict[str, str] | None,
) -> dict[str, str]:
    """Auth + content headers for a connector. Handles bearer/custom-scheme,
    HTTP basic, and APIM-style extra-header creds -- shared by REST and GraphQL
    so a GraphQL service needing basic/extra-header auth works like REST."""
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if basic:
        raw = tok if ":" in tok else f"{tok}:x"
        h["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode("ascii")
    else:
        h[token_header] = f"{scheme} {tok}".strip()
    for hdr, env_name in (extra_headers_env or {}).items():
        val = os.environ.get(env_name, "").strip()
        if val:
            if _requires_scoped_connection():
                raise _ConnectorConfigError(reason="ambient_extra_header")
            h[hdr] = val
    return h


def _rest_response(response, data: Any, args: dict[str, Any], token: str) -> str:
    """Preserve small legacy bodies; never pass a cut JSON document as complete."""
    rendered = json.dumps(data, default=str)
    metadata = args.get("response_format") == "metadata" or response.status_code == 202
    if not metadata and len(rendered) <= _RESPONSE_LIMIT:
        return rendered
    headers = {}
    omitted_headers = []
    # Deliberately exclude cookies, authorization, arbitrary headers and URLs
    # carrying signed query strings. ETags provide the existing If-Match input.
    for name in ("etag", "last-modified", "retry-after"):
        value = getattr(response, "headers", {}).get(name)
        if (isinstance(value, str) and len(value) <= 512
                and not any(ord(c) < 32 or ord(c) == 127 for c in value)
                and not (token and token in value)):
            # Count the encoded size too: three 512-character non-ASCII
            # headers can exceed the entire envelope before any preview fits.
            if len(json.dumps(value)) <= 514:
                headers[name] = value
            else:
                omitted_headers.append(name)
    payload = {"status_code": response.status_code, "headers": headers,
               "truncated": False, "body": data}
    if omitted_headers:
        payload["omitted_headers"] = omitted_headers
    if response.status_code == 202:
        payload["pending"] = True
        payload["note"] = "Accepted for processing; completion has not been verified."
    result = json.dumps(payload, default=str)
    if len(result) <= _RESPONSE_LIMIT:
        return result
    del payload["body"]
    payload.update(truncated=True, response_chars=len(rendered),
                   note="Partial response only; request smaller pages before drawing conclusions.",
                   preview=rendered[:_RESPONSE_LIMIT])
    result = json.dumps(payload)
    while len(result) > _RESPONSE_LIMIT:
        payload["preview"] = payload["preview"][:max(0, len(payload["preview"]) - (len(result) - _RESPONSE_LIMIT))]
        result = json.dumps(payload)
    return result


def _execute_connector_http(method, url, request_headers, *, params, body, args,
                            token, operation, label):
    """One physical HTTP attempt; metadata survives the public string preview."""
    import httpx

    from ..connector_attempts import (
        ConnectorAttempt,
        ConnectorDeadlineExceeded,
        ConnectorResponseLimit,
        ConnectorResult,
        current_invocation,
        retry_after_seconds,
    )
    from ._bounded_http import AttemptDeadline, parse_json_bounded, read_bounded
    from ._ssrf import BlockedHost, safe_client

    invocation = current_invocation()
    # Freeze auth/target/input identity across retries, retaining only a digest.
    # A changed credential or request must start a new reviewed invocation.
    invocation.bind_request(operation, {"url": url, "headers": request_headers,
                                        "params": params, "body": body, "args": args})
    attempt, expires = invocation.begin_attempt()
    deadline = AttemptDeadline(invocation, expires)
    dispatched = False
    status = None

    def outcome(text, error_class=None, retry_after=None, unknown=False):
        if unknown:
            text = ("INDETERMINATE: connector request may have executed; reconcile "
                    "before retrying. "
                    f"request_id={invocation.request_id}; attempt={attempt}")
        return ConnectorResult(text, ConnectorAttempt(
            request_id=invocation.request_id, attempt=attempt, operation=operation,
            status_code=status, error_class=error_class, retry_after=retry_after,
            dispatch_may_have_happened=dispatched, outcome_unknown=unknown))

    try:
        request_headers = {"Accept-Encoding": "identity", **request_headers}
        with safe_client(url, timeout=deadline.remaining(), attempt_deadline=deadline) as client:
            deadline.remaining()
            dispatched = True
            with client.stream(method, url, headers=request_headers,
                               params=params, json=body) as response:
                status = response.status_code
                if status >= 300:
                    klass = ("rate_limit" if status == 429 else "server_5xx" if status >= 500
                             else "auth" if status in {401, 403} else "upstream_rejected")
                    detail = ("redirect or conditional response; no completed result returned"
                              if 300 <= status < 400 else "upstream request failed")
                    return outcome(f"ERROR: {label} ({status}): {detail}", klass,
                                   retry_after_seconds(response.headers.get("retry-after")),
                                   unknown=operation != "safe_read" and status >= 500)
                raw = read_bounded(response, invocation.limits, deadline)
                try:
                    data = parse_json_bounded(raw, invocation.limits, deadline)
                except ConnectorResponseLimit:
                    raise
                except (ValueError, UnicodeError):
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    # Any 2xx with an empty body completed; only GraphQL must carry data.
                    no_content = not raw and 200 <= status < 300 and label != "graphql"
                    if not no_content and (label == "graphql" or content_type == "application/json"
                                           or content_type.endswith("+json")):
                        return outcome(f"ERROR: {label} ({status}): invalid upstream response",
                                       "malformed_response", unknown=operation != "safe_read")
                    try:
                        data = raw.decode(response.encoding or "utf-8", errors="replace")
                    except LookupError:
                        data = raw.decode("utf-8", errors="replace")
                if label == "graphql":
                    if not isinstance(data, dict) or data.get("errors"):
                        return outcome(f"ERROR: graphql ({status}): upstream request failed",
                                       "graphql_error", unknown=operation == "mutation")
                    if "data" not in data:
                        return outcome(f"ERROR: graphql ({status}): invalid upstream response",
                                       "malformed_response", unknown=operation != "safe_read")
                    data = data["data"]
                return outcome(_rest_response(response, data, args, token))
    except CONTROL_ERRORS:
        raise
    except BlockedHost:
        return outcome("ERROR: blocked host (SSRF guard)", "blocked_host")
    except (ConnectorResponseLimit, ConnectorDeadlineExceeded) as exc:
        invocation.check()
        kind = "response_limit" if isinstance(exc, ConnectorResponseLimit) else "deadline"
        return outcome(f"ERROR: connector {kind}; no complete response was admitted",
                       kind, unknown=dispatched and operation != "safe_read")
    except (httpx.ConnectError, httpx.ConnectTimeout):
        # The connection was never established, so no request bytes left.
        invocation.check()
        dispatched = False
        return outcome(f"ERROR: {label} request failed (could not connect)",
                       "transient_network")
    except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError):
        invocation.check()
        return outcome(f"ERROR: {label} request failed (transport failure)",
                       "transient_network", unknown=dispatched and operation != "safe_read")
    except RuntimeError:
        invocation.check()
        return outcome("ERROR: connector configuration or request failed (RuntimeError)",
                       "invalid_response", unknown=dispatched and operation != "safe_read")
    except Exception:
        invocation.check()
        return outcome(f"ERROR: {label} request failed (invalid response or transport failure)",
                       "invalid_response", unknown=dispatched and operation != "safe_read")


def _rest_execute(
    op: str,
    path: str,
    args: dict[str, Any],
    *,
    name: str,
    config,
    headers,
    norm,
    query_auth: str | None = None,
) -> str:
    """Perform the authenticated REST request and render the response."""
    params = args.get("params") if isinstance(args.get("params"), dict) else None
    body = args.get("body") if isinstance(args.get("body"), dict) else None
    try:
        base, tok = config()
        # Query-param auth: the credential rides a query param (e.g. FRED's
        # ``api_key``, Census's ``key``) rather than a header. Caller-supplied
        # params cannot replace it: the configured credential always wins.
        if query_auth and tok:
            params = {**(params or {}), query_auth: tok}
        url = f"{base}{norm(path)}"
        # Enterprise mode: a connector POSTs agent-supplied content to a
        # third-party SaaS host -- hold it to the egress boundary too.
        if deny := _capability_egress_denial(url, args, name=name):
            return f"ERROR: {deny}"
        from ..enterprise import enterprise_egress_denial
        deny = enterprise_egress_denial(url, tool=name)
        if deny:
            return f"ERROR: {deny}"
        # Route through the SSRF-safe client: resolve the host ONCE and pin the
        # connection to that validated public IP, so DNS-rebinding can't point
        # the configured connector host at an internal/metadata address
        # (169.254.169.254, 127.0.0.1) after the egress check above. The bearer
        # token rides this request, so an unpinned fetch could exfil it. Redirects
        # stay off (safe_client default) -- only ``url`` passed the gate. On-prem
        # connectors opt in via MAVERICK_FETCH_ALLOW_PRIVATE=1.
        request_headers = headers(tok)
        if_match = args.get("if_match")
        if isinstance(if_match, str) and if_match.strip():
            request_headers["If-Match"] = if_match.strip()
        return _execute_connector_http(
            op.upper(), url, request_headers, params=params or None, body=body,
            args=args, token=tok, operation="safe_read" if op == "get" else "mutation", label=op)
    except CONTROL_ERRORS:
        raise
    except _ConnectorConfigError as e:
        return f"ERROR: {e}"
    except RuntimeError:
        return "ERROR: connector configuration or request failed (RuntimeError)"
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {name} request failed ({type(e).__name__[:120]})"

