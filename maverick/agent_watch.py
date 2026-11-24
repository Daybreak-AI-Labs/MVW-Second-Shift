"""Platform checks ("watchers") for enrolled outside agents.

Second Shift otherwise knows only what an enrolled agent tells it. A watcher
asks the agent's home platform directly which agents exist there and how each
is configured, so a configuration change shows even when the agent does not
report it, and an agent that exists on the platform but was never enrolled is
listed:

* ``ObservedAgent`` / ``Watcher`` / ``register`` -- the interface a platform
  module implements: a name, and ``list_agents()`` returning every agent the
  platform has, each with a fingerprint of its configuration.
* ``Reader`` / ``odata_next`` / ``client_credentials_token`` /
  ``secret_named`` / ``env_name`` / ``fingerprint`` / ``unexpected_answer`` --
  what a watcher is built from: guarded, bounded GETs with paging caps, an
  OAuth 2.0 client-credentials sign-in kept in memory, and secrets read by
  environment-variable name.
* ``sync`` -- list every configured platform, match what was found to enrolled
  agents through their ``external_ref`` (``"<platform>:<external_id>"``), hand
  each match's fingerprint to ``agent_drift.observe_discovered``, and remember
  the rest as "found on the platform, not enrolled".
* ``status`` / ``unenrolled`` / ``platform_view`` -- read models for a UI.

What it does not do. It only reads: a watcher makes a fixed set of GET calls
(plus the sign-in), and nothing a caller passes in can change an address, a
query or a method. It never changes, disables or deletes anything on a
platform, and it does not contain or alert; a changed fingerprint becomes a
drift finding through ``agent_drift``, which decides what happens next. It
keeps names, states, version labels and fingerprints, never a platform's raw
answer, and no token or secret is stored, logged or put in a message. It sees
only what the configured platforms list to the account it signs in with.

A platform's run either yields its complete list or fails: reaching a cap, a
malformed page or a paging loop is an error, never a shorter list. One
platform failing does not stop the others and leaves what was known about it
untouched. The record lives in one JSON file beside the enrollment sidecar,
written atomically under a cross-process lock and bounded in every direction.
A file that cannot be read is never replaced and never read as empty: every
entry point raises :class:`AgentWatchStoreError`, before any platform is asked.

Off by default: ``[agent_watch] enable = true`` (or ``MAVERICK_AGENT_WATCH=1``)
turns it on wherever outside-agent governance is on.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import SplitResult, urlsplit

log = logging.getLogger("maverick.agent_watch")

SCHEMA_VERSION = 1

#: ``ObservedAgent.binding_strength``: the platform gave an immutable version
#: id, or the fingerprint is only a snapshot of what was readable at the time.
IMMUTABLE_REVISION = "immutable_provider_revision"
OBSERVED_SNAPSHOT = "observed_snapshot"
_BINDINGS = (IMMUTABLE_REVISION, OBSERVED_SNAPSHOT)
_STATES = ("enabled", "disabled", "")

#: Modules that register the built-in watchers when imported.
_WATCHER_MODULES = ("agent_watch_microsoft", "agent_watch_servicenow", "agent_watch_workday")

#: Storage bounds. Platforms follow the settings cap, per-agent views follow
#: enrollment, and each platform keeps a capped not-enrolled list.
_MAX_PLATFORMS = 20
_MAX_UNENROLLED = 500
_MAX_COUNT = 10 ** 9
_MAX_NAME = 120
_MAX_LABEL = 80
_MAX_ERROR = 300

#: Read bounds that are not settings.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
_MAX_URL = 16 * 1024
#: One platform run may take this many per-request timeouts in total.
_RUN_TIMEOUTS = 15

#: A token is dropped this long before the platform says it expires.
_TOKEN_MARGIN_SECONDS = 120
_MAX_TOKENS = 32

_NAME = re.compile(r"[a-z][a-z0-9_]{0,39}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_EXTERNAL_ID = re.compile(r"[^\s\x00-\x1f\x7f]{1,200}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,39}")
_TOKEN_TEXT = re.compile(r"[\x21-\x7e]{1,16384}")

#: ``[agent_watch]`` number settings: name -> (default, lowest, highest).
_NUMBER_SETTINGS: dict[str, tuple[int, int, int]] = {
    # how often the web app runs a check
    "sync_minutes": (60, 5, 1440),
    # successful runs in a row an enrolled agent may be absent before it is marked missing
    "missing_after_runs": (3, 1, 30),
    # per platform run: the most agents, the most requests, and seconds per request
    "max_agents": (2000, 1, 20000),
    "max_pages": (100, 1, 1000),
    "timeout_seconds": (20, 2, 120),
}
_RESERVED = frozenset({"enable", "platforms", *_NUMBER_SETTINGS})

_OFF_REASON = "Platform checks are turned off."
_GOVERNANCE_OFF_REASON = "Outside-agent governance is turned off, so platform checks do not run."
_BUSY_REASON = "A platform check is already running."

_UNEXPECTED_FORM = "The platform's answer was not in the expected form, so nothing from this check was used."
_TOO_LARGE = "The platform's answer was larger than this check accepts, so nothing from this check was used."
_NOT_IN_TIME = "The platform did not answer in time."
_UNREACHABLE = "The platform could not be reached."
_NOT_ALLOWED = "The address this check uses is not allowed or could not be found."
_EGRESS_BLOCKED = "This installation's network rules do not allow connections to the platform."
_LEFT_ADDRESS = ("The platform's answer pointed to a different address from the one being checked, "
                 "so the check stopped.")
_UNEXPECTED_FAILURE = "The check stopped because of an unexpected problem. The server log has the details."


class AgentWatchError(Exception):
    """Operator-facing failure. The message is plain language and holds no
    secret and nothing copied from a platform's answer."""


class AgentWatchStoreError(AgentWatchError):
    """The saved platform record, or the enrollment record, cannot be read."""


class WatchError(AgentWatchError):
    """One platform's run could not finish. Watchers raise it; ``sync`` keeps
    the message as that platform's last error."""


class WatchConfigError(WatchError):
    """A platform's ``[agent_watch.<name>]`` settings cannot be used."""


@dataclass(frozen=True)
class ObservedAgent:
    """One agent as its home platform lists it.

    ``fingerprint`` is a sha256 hex digest over the values that define the
    agent's configuration, worked out by the watcher from normalised values
    (see :func:`fingerprint`), never over the platform's raw answer.
    ``updated_at`` is whatever timestamp text the platform gives, ``state`` is
    "enabled", "disabled" or "" when the platform does not say."""

    platform: str
    external_id: str
    name: str = ""
    version: str = ""
    updated_at: str = ""
    state: str = ""
    fingerprint: str = ""
    binding_strength: str = OBSERVED_SNAPSHOT


class Watcher(Protocol):
    """What a platform module provides. ``list_agents`` returns every agent
    the platform has, or raises :class:`WatchError`; it never returns part of
    the list."""

    name: str

    def list_agents(self) -> list[ObservedAgent]: ...


_FACTORIES: dict[str, Callable[[dict], Watcher]] = {}


def register(name: str, factory: Callable[[dict], Watcher]) -> None:
    """Make a watcher available under its platform name.

    ``factory`` is called with a copy of the ``[agent_watch.<name>]`` table and
    returns the watcher, or raises :class:`WatchConfigError` saying what is
    wrong with the settings. It only checks settings: no network call is made
    and no secret is read there, because ``status`` calls it too."""
    if not isinstance(name, str) or not _NAME.fullmatch(name) or name in _RESERVED:
        raise ValueError("a platform name is lower-case letters, digits and underscores")
    _FACTORIES[name] = factory


def registered() -> list[str]:
    """The platform names a watcher is available for."""
    _load_watchers()
    return sorted(_FACTORIES)


_watchers_tried: set[str] = set()


def _load_watchers() -> None:
    """Import the built-in watcher modules, once each. One that cannot be
    imported is logged and left out; its platforms then read as unavailable."""
    for module in _WATCHER_MODULES:
        if module in _watchers_tried:
            continue
        _watchers_tried.add(module)
        try:
            importlib.import_module(f".{module}", __package__)
        except Exception:
            log.warning("agent_watch: the built-in checks in %s could not be loaded", module,
                        exc_info=True)


def fingerprint(parts: Mapping[str, Any]) -> str:
    """A sha256 hex digest over named configuration values.

    The same values give the same digest whatever order the names come in.
    Values are text, whole numbers, true/false, nothing, or lists and maps of
    those; a list keeps its order, so sort one whose order means nothing. Hash
    long text (instructions, a configuration blob) before passing it in."""
    canonical = json.dumps(_plain(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {key: _plain(item) for key, item in value.items()}
    raise TypeError("a fingerprint is made from text, whole numbers, true/false, lists and maps")


def unexpected_answer() -> WatchError:
    """The error a watcher raises when a platform's answer is not in the form
    its documentation gives. The wording says nothing about the answer itself."""
    return WatchError(_UNEXPECTED_FORM)


def env_name(table: Mapping[str, Any], key: str, section: str) -> str:
    """The environment-variable name a setting holds. Raises
    :class:`WatchConfigError` when it is missing or is not a name; the value is
    never repeated, in case a secret was typed where its name belongs."""
    value = table.get(key)
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        raise WatchConfigError(
            f"{section} needs {key}: the name of an environment variable (letters, digits and "
            "underscores), not the value itself.")
    return value


def secret_named(variable: str, setting: str) -> str:
    """The value of the environment variable (or mounted secret file) called
    ``variable``, read now. ``setting`` says where the name came from, for the
    message when nothing is set; the name itself is not repeated."""
    from .secret_provider import get_secret
    value = get_secret(variable)
    if not isinstance(value, str) or not value.strip():
        raise WatchError(f"The environment variable named by {setting} is not set.")
    return value.strip()


def settings() -> dict:
    """The validated ``[agent_watch]`` section.

    ``enable`` (default off), ``platforms`` (watcher names, in order),
    ``sync_minutes``, ``missing_after_runs``, ``max_agents``, ``max_pages`` and
    ``timeout_seconds``. Numbers outside their range are clamped and a
    malformed one falls back to its default. ``problems`` lists, in plain
    words, anything that could not be used; a value is never repeated there.
    ``platforms_readable`` is false when ``platforms`` itself was not a list.
    Each platform's own table is checked by its watcher (see ``status``).
    ``MAVERICK_AGENT_WATCH=0/1`` overrides ``enable``."""
    section, problems = _section()
    flag = section.get("enable")
    out: dict[str, Any] = {"enable": flag if isinstance(flag, bool) else False}
    for name, (default, low, high) in _NUMBER_SETTINGS.items():
        out[name] = _clamped(section.get(name), default, low, high)
    out["platforms"], out["platforms_readable"] = _platform_names(section.get("platforms"), problems)
    out["problems"] = problems
    from .config import env_flag
    override = env_flag("MAVERICK_AGENT_WATCH")
    if override is not None:
        out["enable"] = override
    return out


def _section() -> tuple[dict, list[str]]:
    try:
        from .config import load_config
        section = (load_config() or {}).get("agent_watch")
    except Exception:
        return {}, ["The settings could not be read, so no platform is checked."]
    if section is None:
        return {}, []
    if not isinstance(section, dict):
        return {}, ["[agent_watch] is not a settings table, so no platform is checked."]
    return section, []


def _clamped(raw: Any, default: int, low: int, high: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return default
    if not math.isfinite(raw) or raw != int(raw):
        return default
    return int(max(low, min(high, raw)))


def _platform_names(raw: Any, problems: list[str]) -> tuple[list[str], bool]:
    """The configured platform names, and whether the list itself was usable."""
    if raw is None:
        return [], True
    if not isinstance(raw, list):
        problems.append("platforms in [agent_watch] must be a list of platform names, so no "
                        "platform is checked.")
        return [], False
    names: list[str] = []
    for position, entry in enumerate(raw[:_MAX_PLATFORMS * 2], start=1):
        name = entry.strip().lower() if isinstance(entry, str) else ""
        if not _NAME.fullmatch(name) or name in _RESERVED:
            problems.append(f"Entry {position} of platforms in [agent_watch] is not a platform "
                            "name, so it is skipped.")
        elif name not in names:
            names.append(name)
    if len(names) > _MAX_PLATFORMS or len(raw) > _MAX_PLATFORMS * 2:
        problems.append(f"Only the first {_MAX_PLATFORMS} platforms in [agent_watch] are checked.")
    return names[:_MAX_PLATFORMS], True


def enabled() -> bool:
    """Whether platform checks run: ``[agent_watch] enable`` (or
    ``MAVERICK_AGENT_WATCH=1``) and outside-agent governance are both on."""
    return _active(settings())


def _active(cfg: dict) -> bool:
    if not cfg["enable"]:
        return False
    from . import external_agents
    return bool(external_agents.enabled())


@dataclass(frozen=True)
class Limits:
    """The bounds on one platform run."""

    timeout_seconds: float = 20.0
    max_pages: int = 100
    max_records: int = 2000
    max_response_bytes: int = _MAX_RESPONSE_BYTES
    run_seconds: float = 300.0


def limits() -> Limits:
    """The run bounds from ``[agent_watch]`` (``timeout_seconds``,
    ``max_pages``, ``max_agents``)."""
    cfg = settings()
    timeout = float(cfg["timeout_seconds"])
    return Limits(timeout_seconds=timeout, max_pages=cfg["max_pages"],
                  max_records=cfg["max_agents"], run_seconds=timeout * _RUN_TIMEOUTS)


def _monotonic() -> float:
    return time.monotonic()


class Reader:
    """The guarded reads of one platform run.

    Every GET goes through the outbound address guard with a timeout and a
    response-size bound, and all of them share the run's page cap, record cap
    and overall time limit, so a watcher cannot pass its limits by splitting
    the work up. Reaching a limit raises :class:`WatchError`."""

    def __init__(self, bounds: Limits | None = None) -> None:
        self._limits = bounds if bounds is not None else limits()
        self._stop_at = _monotonic() + self._limits.run_seconds
        self._requests = 0
        self._records = 0

    def get(self, url: str, *, bearer: str, headers: Mapping[str, str] | None = None) -> dict:
        """One GET, answered with a JSON object. Anything else (another
        status, a redirect, a body that is too large or is not an object) is
        an error, worded without the platform's own text."""
        self._requests += 1
        if self._requests > self._limits.max_pages:
            raise WatchError(
                f"The platform's list did not end within {self._limits.max_pages} pages, so the "
                "check stopped and nothing from it was used. If the list really is that long, "
                "raise max_pages in [agent_watch].")
        left = self._stop_at - _monotonic()
        if left <= 0:
            raise WatchError(_NOT_IN_TIME)
        sent = {"Accept": "application/json", **dict(headers or {}), "Authorization": f"Bearer {bearer}"}
        status, body = _request("GET", url, headers=sent, timeout=min(self._limits.timeout_seconds, left),
                                max_bytes=self._limits.max_response_bytes)
        if status == 200:
            return _json_object(body)
        if status == 401:
            _forget_token(bearer)
        raise WatchError(_status_message(status))

    def records(self, url: str, *, bearer: str, items: str,
                next_url: Callable[[dict, str], str | None],
                headers: Mapping[str, str] | None = None) -> Iterator[dict]:
        """Every record of a paged list, one at a time, so a watcher keeps
        what it needs from each and the page it came in can be let go.
        ``items`` names the list inside each page; ``next_url(page, url)``
        gives the next page's address or ``None`` at the end (``odata_next``
        does this for ``@odata.nextLink``). Nothing is read until the records
        are asked for, and a limit or a malformed page raises from there."""
        visited: set[str] = set()
        current: str | None = url
        while current is not None:
            if current in visited:
                raise WatchError("The platform's list kept pointing back to a page already read "
                                 "(a repeat), so the check stopped and nothing from it was used.")
            visited.add(current)
            page = self.get(current, bearer=bearer, headers=headers)
            batch = page.get(items)
            if not isinstance(batch, list) or not all(isinstance(row, dict) for row in batch):
                raise unexpected_answer()
            self._records += len(batch)
            if self._records > self._limits.max_records:
                raise WatchError(
                    f"The platform listed more than {self._limits.max_records} agents, so the "
                    "check stopped and nothing from it was used. Raise max_agents in "
                    "[agent_watch] if that many are expected.")
            yield from batch
            current = next_url(page, current)


def odata_next(page: dict, url: str) -> str | None:
    """The next page's address from ``@odata.nextLink``, or ``None`` on the
    last page. The link is used exactly as given, and only when it stays on the
    address being read (https, same host and port, same path)."""
    link = page.get("@odata.nextLink")
    if link is None:
        return None
    if not isinstance(link, str) or not link or len(link) > _MAX_URL:
        raise unexpected_answer()
    if _place(link) != _place(url):
        raise WatchError(_LEFT_ADDRESS)
    return link


def _place(url: str) -> tuple[str, int, str]:
    """Host, port and path of an https address, for comparing two of them."""
    parts = _https(url)
    return (parts.hostname or "").lower(), parts.port or 443, parts.path.rstrip("/").casefold()


def _https(url: str) -> SplitResult:
    """``url`` split up, refused unless it is a plain https address."""
    try:
        parts = urlsplit(url)
        _ = parts.port  # a malformed port raises here, not later
    except ValueError:
        raise WatchError(_NOT_ALLOWED) from None
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise WatchError(_NOT_ALLOWED)
    return parts


def _request(method: str, url: str, *, headers: Mapping[str, str], timeout: float, max_bytes: int,
             form: Mapping[str, str] | None = None, error_body: bool = False) -> tuple[int, bytes]:
    """Send one request through the outbound guard. Returns the status and the
    body: the whole body of a 200 (an error if it passes ``max_bytes``), the
    start of any other answer when ``error_body``, otherwise nothing."""
    import httpx

    from .enterprise import EgressBlocked
    from .tools import _ssrf
    _https(url)
    stop_at = _monotonic() + timeout
    try:
        with _ssrf.safe_client(url, timeout=timeout) as client:
            with client.stream(method, url, headers=dict(headers), data=form) as response:
                status = response.status_code
                if status != 200 and not error_body:
                    return status, b""
                return status, _bounded_body(response, max_bytes, stop_at, strict=status == 200)
    except WatchError:
        raise
    except _ssrf.BlockedHost:
        raise WatchError(_NOT_ALLOWED) from None
    except EgressBlocked:
        raise WatchError(_EGRESS_BLOCKED) from None
    except httpx.TimeoutException:
        raise WatchError(_NOT_IN_TIME) from None
    except (httpx.HTTPError, httpx.InvalidURL, OSError):
        raise WatchError(_UNREACHABLE) from None


def _bounded_body(response: Any, max_bytes: int, stop_at: float, *, strict: bool) -> bytes:
    body = bytearray()
    for chunk in response.iter_bytes(chunk_size=65536):
        if len(body) + len(chunk) > max_bytes:
            if strict:
                raise WatchError(_TOO_LARGE)
            return bytes(body)
        body.extend(chunk)
        # The client's timeout is per read; a body sent a little at a time
        # would never trip it.
        if _monotonic() > stop_at:
            raise WatchError(_NOT_IN_TIME)
    return bytes(body)


def _json_object(body: bytes) -> dict:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        raise unexpected_answer() from None
    if not isinstance(parsed, dict):
        raise unexpected_answer()
    return parsed


def _status_message(status: int) -> str:
    if status == 401:
        return ("The platform did not accept this check's sign-in (HTTP 401). Check the client id "
                "and secret, and that the secret has not expired.")
    if status == 403:
        return ("The platform refused this check (HTTP 403). The permission it needs has probably "
                "not been granted yet.")
    if status == 404:
        return ("The platform has nothing at the address this check uses (HTTP 404). Check the "
                "addresses in the settings.")
    if status == 429:
        return ("The platform is limiting requests at the moment (HTTP 429). The next check will "
                "try again.")
    if 300 <= status < 400:
        return f"The platform answered with a redirect (HTTP {status}), which this check does not follow."
    return f"The platform answered with HTTP {status}, which this check does not expect."


#: (token address, client id, scope) -> (token, monotonic time it is dropped).
#: Memory only: a token is never written anywhere.
_TOKENS: dict[tuple[str, str, str], tuple[str, float]] = {}
_token_lock = threading.Lock()


def client_credentials_token(token_url: str, *, client_id: str, client_secret: str, scope: str,
                             timeout: float | None = None) -> str:
    """A bearer token from an OAuth 2.0 client-credentials sign-in (RFC 6749
    section 4.4): one form POST of ``grant_type``, ``client_id``,
    ``client_secret`` and ``scope`` to ``token_url``.

    The token is kept in memory until shortly before it expires and reused for
    the same address, client and scope. A refused sign-in raises
    :class:`WatchError` carrying the service's short error code and nothing
    else from its answer."""
    key = (token_url, client_id, scope)
    with _token_lock:
        kept = _TOKENS.get(key)
        if kept is not None and kept[1] > _monotonic():
            return kept[0]
        _TOKENS.pop(key, None)
    token, lifetime = _sign_in(token_url, client_id, client_secret, scope,
                               limits().timeout_seconds if timeout is None else timeout)
    if lifetime > _TOKEN_MARGIN_SECONDS:
        with _token_lock:
            _make_room_for_a_token()
            _TOKENS[key] = (token, _monotonic() + lifetime - _TOKEN_MARGIN_SECONDS)
    return token


def _sign_in(token_url: str, client_id: str, client_secret: str, scope: str,
             timeout: float) -> tuple[str, float]:
    """The token and its lifetime in seconds (0 when the answer gives none)."""
    form = {"grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "scope": scope}
    status, body = _request("POST", token_url, headers={"Accept": "application/json"}, form=form,
                            timeout=timeout, max_bytes=_MAX_TOKEN_RESPONSE_BYTES, error_body=True)
    if status != 200:
        raise WatchError(_refused_sign_in(status, body))
    answer = _sign_in_answer(body)
    token, kind = answer.get("access_token"), answer.get("token_type")
    if (not isinstance(token, str) or not _TOKEN_TEXT.fullmatch(token)
            or (kind is not None and str(kind).lower() != "bearer")):
        raise WatchError("The sign-in service's answer held no usable token, so the check did not run.")
    return token, _lifetime(answer.get("expires_in"))


def _sign_in_answer(body: bytes) -> dict:
    try:
        return _json_object(body)
    except WatchError:
        raise WatchError("The sign-in service's answer could not be read, so the check did not "
                         "run.") from None


def _refused_sign_in(status: int, body: bytes) -> str:
    """Why a sign-in was refused, using only the service's short error code."""
    try:
        code = _json_object(body).get("error")
    except WatchError:
        code = None
    reason = f" ({code})" if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else ""
    return (f"The sign-in service refused this check's sign-in{reason}, HTTP {status}. Check the "
            "tenant id, the client id and the client secret, and that the secret has not expired.")


def _lifetime(expires_in: Any) -> float:
    if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
        return 0.0
    return float(expires_in) if math.isfinite(expires_in) and expires_in > 0 else 0.0


def _make_room_for_a_token() -> None:
    now = _monotonic()
    for key in [key for key, (_token, until) in _TOKENS.items() if until <= now]:
        del _TOKENS[key]
    while len(_TOKENS) >= _MAX_TOKENS:
        del _TOKENS[min(_TOKENS, key=lambda key: _TOKENS[key][1])]


def _forget_token(token: str) -> None:
    """Drop a token the platform no longer accepts, so the next run signs in again."""
    with _token_lock:
        for key in [key for key, (kept, _until) in _TOKENS.items() if kept == token]:
            del _TOKENS[key]


def store_path() -> Path:
    """The platform record (``external_agents_watch.json``), in the same
    tenant-scoped directory as the enrollment sidecar."""
    from .external_agents import registry_path
    return registry_path().with_name("external_agents_watch.json")


def _load_store(path: Path | None = None) -> dict[str, dict]:
    """The saved record: ``platforms``, ``unenrolled`` and ``agents``. A
    missing file is an empty record. A file that cannot be read or understood
    raises, so no caller mistakes it for "nothing known" and nothing is
    written over it."""
    path = path or store_path()
    try:
        if not path.exists():
            return {"platforms": {}, "unenrolled": {}, "agents": {}}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != SCHEMA_VERSION:
            raise ValueError("unknown platform record layout")
        store = {name: data.get(name) for name in ("platforms", "unenrolled", "agents")}
        if not _well_formed(store):
            raise ValueError("platform record holds a malformed entry")
        return store
    except (OSError, UnicodeError, ValueError, RecursionError) as e:
        raise AgentWatchStoreError(
            "The saved platform record cannot be read, so nothing was checked or changed. "
            "Restore it from a backup, or move the file aside to start a new record.") from e


def _well_formed(store: dict) -> bool:
    if not all(isinstance(group, dict) for group in store.values()):
        return False
    return (all(isinstance(record, dict) for record in store["platforms"].values())
            and all(isinstance(view, dict) for view in store["agents"].values())
            and all(isinstance(found, dict) and all(isinstance(entry, dict) for entry in found.values())
                    for found in store["unenrolled"].values()))


def _dump(store: dict[str, dict]) -> str:
    return json.dumps({"version": SCHEMA_VERSION, **store}, sort_keys=True, separators=(",", ":"))


@contextmanager
def _editing() -> Iterator[dict[str, dict]]:
    """The record, held under its cross-process lock for one read-modify-write.

    Whatever the block leaves in it is written back, atomically, when it
    differs from what was read. An unreadable file raises before the block runs
    and a block that raises writes nothing. The block must not call a platform
    (the lock would be held for as long as the platform takes) and must not
    take the enrollment sidecar lock."""
    from .file_lock import atomic_write_text, cross_process_lock, ensure_private_directory
    path = store_path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        store = _load_store(path)
        before = _dump(store)
        yield store
        after = _dump(store)
        if after != before:
            atomic_write_text(path, after, mode=0o600)


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _count(value: Any) -> int:
    """A stored count, read defensively; junk reads as 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(min(max(value, 0), _MAX_COUNT)) if math.isfinite(value) else 0


def _stamp(value: Any) -> float | None:
    """A stored time, read defensively; junk reads as "never"."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and value > 0 else None


def _text(value: Any, limit: int = _MAX_LABEL) -> str:
    """Display text from a platform: one line, printable, bounded, and dropped
    altogether when it looks like it carries a secret."""
    if not isinstance(value, str):
        return ""
    text = "".join(ch for ch in " ".join(value.split()) if ch.isprintable())[:limit]
    return "" if _looks_secret(text) else text


def _looks_secret(text: str) -> bool:
    try:
        from .safety.secret_detector import redact
        return redact(text)[0] != text
    except Exception:
        return True  # cannot check it, so do not keep it


def _safe_message(text: Any) -> str:
    """An error message as it is kept and shown: bounded, with anything that
    looks like a secret taken out."""
    try:
        from .safety.secret_detector import redact
        from .secrets import scrub
        clean = scrub(redact(" ".join(str(text).split()))[0])
    except Exception:
        return _UNEXPECTED_FAILURE
    return clean[:_MAX_ERROR].strip() or _UNEXPECTED_FAILURE


def _now(now: float | None) -> float:
    if now is None:
        return time.time()
    moment = float(now)
    return moment if math.isfinite(moment) else time.time()


def _key(external_id: str) -> str:
    return external_id.strip().casefold()


def _parse_ref(value: Any) -> tuple[str, str] | None:
    """``"<platform>:<external_id>"`` as (platform, external id), or ``None``
    when the value is absent or is not in that form."""
    if not isinstance(value, str):
        return None
    platform, colon, external_id = value.strip().partition(":")
    platform, external_id = platform.strip().lower(), external_id.strip()
    if not colon or not _NAME.fullmatch(platform) or not _EXTERNAL_ID.fullmatch(external_id):
        return None
    return platform, external_id


def _enrolled_refs() -> dict[str, tuple[str, str, str]]:
    """Enrolled agent id -> (external_ref as written, platform, match key), for
    the agents that have a usable ``external_ref``. A strict read: enrollment
    that cannot be read raises instead of looking like an empty roster."""
    from . import external_agents
    try:
        sidecar = external_agents._load_sidecar(strict=True)
    except external_agents.ExternalAgentsDependencyError as e:
        raise AgentWatchStoreError(
            "The enrollment record cannot be read, so nothing was checked or changed.") from e
    refs: dict[str, tuple[str, str, str]] = {}
    for agent_id, entry in sidecar.items():
        parsed = _parse_ref(entry.get("external_ref"))
        if parsed is not None:
            refs[agent_id] = (f"{parsed[0]}:{parsed[1]}", parsed[0], _key(parsed[1]))
    return refs


_sync_lock = threading.Lock()


def sync(*, now: float | None = None) -> dict:
    """Ask every configured platform for its agents and bring the record up to
    date.

    For each platform that answers: an agent matching an enrolled agent's
    ``external_ref`` has its fingerprint handed to
    ``agent_drift.observe_discovered``; the others are kept as "found on the
    platform, not enrolled"; and an enrolled agent the platform did not list
    has its absence counted, becoming ``missing_on_platform`` after
    ``missing_after_runs`` successful runs in a row without it. A platform
    that fails keeps everything known about it and records why.

    Returns ``{"enabled", "ran", "at", "platforms": {name: {"ok", "error",
    "listed", "matched", "not_enrolled", "missing"}}, "succeeded", "failed",
    "listed", "matched", "not_enrolled", "missing_on_platform"}``; a platform
    that failed has only ``ok`` and ``error``. Does nothing, and
    says why in ``reason``, when platform checks are off or a check is already
    running. Audited as ``agent_watch_synced`` with counts only. Raises
    :class:`AgentWatchStoreError`, before any platform is asked, when the saved
    record or the enrollment record cannot be read."""
    cfg = settings()
    if not _active(cfg):
        reason = _OFF_REASON if not cfg["enable"] else _GOVERNANCE_OFF_REASON
        return {"enabled": False, "ran": False, "platforms": {}, "reason": reason}
    if not _sync_lock.acquire(blocking=False):
        return {"enabled": True, "ran": False, "platforms": {}, "reason": _BUSY_REASON}
    try:
        return _sync(cfg, _now(now))
    finally:
        _sync_lock.release()


def _sync(cfg: dict, moment: float) -> dict:
    _load_store()  # refuse now, not after the platforms have been asked
    refs = _enrolled_refs()
    cap = cfg["max_agents"]
    runs = {name: _run(name, cap) for name in cfg["platforms"]}
    with _editing() as store:
        _forget(store, cfg, refs)
        results = {name: _apply(store, name, found, error, refs, cfg, moment)
                   for name, (found, error) in runs.items()}
        summary = _summary(results, moment)
        _audit(summary)
    _tell_drift(runs, refs, moment)
    log.info("agent_watch: checked %d platform(s): %d ok, %d failed, %d matched, %d not enrolled",
             len(results), summary["succeeded"], summary["failed"], summary["matched"],
             summary["not_enrolled"])
    return summary


def _run(name: str, cap: int) -> tuple[list[ObservedAgent] | None, str]:
    """One platform's complete list, or ``None`` and why it could not be had."""
    try:
        return _checked(_build(name).list_agents(), name, cap), ""
    except WatchError as e:
        message = _safe_message(e)
        log.warning("agent_watch: the %s check did not finish: %s", name, message)
        return None, message
    except Exception as e:
        # The text of an unexpected failure may hold anything; log its type only.
        log.warning("agent_watch: the %s check stopped unexpectedly (%s)", name, type(e).__name__)
        return None, _UNEXPECTED_FAILURE


def _build(name: str) -> Watcher:
    """The watcher for a configured platform, made from its settings table."""
    _load_watchers()
    factory = _FACTORIES.get(name)
    if factory is None:
        known = ", ".join(sorted(_FACTORIES)) or "none"
        raise WatchConfigError(f"There is no platform check called {name}. Available: {known}.")
    table = _section()[0].get(name, {})
    if not isinstance(table, dict):
        raise WatchConfigError(f"[agent_watch.{name}] must be a settings table.")
    try:
        return factory(copy.deepcopy(table))
    except WatchConfigError:
        raise
    except Exception:
        raise WatchConfigError(f"The [agent_watch.{name}] settings could not be used.") from None


def _checked(found: Any, name: str, cap: int) -> list[ObservedAgent]:
    """A watcher's answer, refused unless every entry is usable. The same
    agent listed twice counts once. Two ids that differ only in letter case
    are refused, because references are matched without regard to case and
    one of the two would otherwise be dropped unseen."""
    if not isinstance(found, list):
        raise unexpected_answer()
    agents: dict[str, ObservedAgent] = {}
    for agent in found:
        if not _usable(agent, name):
            raise unexpected_answer()
        if agents.setdefault(_key(agent.external_id), agent).external_id != agent.external_id:
            raise WatchError("The platform listed two agents whose ids differ only in capital "
                             "and small letters, which this check cannot tell apart.")
    if len(agents) > cap:
        raise WatchError(f"The platform listed more than {cap} agents, so nothing from this check "
                         "was used. Raise max_agents in [agent_watch] if that many are expected.")
    return list(agents.values())


def _usable(agent: Any, name: str) -> bool:
    return (isinstance(agent, ObservedAgent) and agent.platform == name
            and isinstance(agent.external_id, str) and bool(_EXTERNAL_ID.fullmatch(agent.external_id))
            and isinstance(agent.fingerprint, str) and bool(_DIGEST.fullmatch(agent.fingerprint))
            and agent.binding_strength in _BINDINGS and agent.state in _STATES)


def _forget(store: dict, cfg: dict, refs: dict) -> None:
    """Drop what no longer applies: the views of agents that are no longer
    enrolled against the same platform agent, and everything about a platform
    taken out of the settings (unless the platform list itself could not be
    read, when nothing is dropped on its account)."""
    views = store["agents"]
    for agent_id in [agent_id for agent_id, view in views.items()
                     if agent_id not in refs or view.get("external_ref") != refs[agent_id][0]]:
        del views[agent_id]
    if not cfg["platforms_readable"]:
        return
    for group in ("platforms", "unenrolled"):
        for name in [name for name in store[group] if name not in cfg["platforms"]]:
            del store[group][name]
    for agent_id in [agent_id for agent_id in views if refs[agent_id][1] not in cfg["platforms"]]:
        del views[agent_id]


def _apply(store: dict, name: str, found: list[ObservedAgent] | None, error: str,
           refs: dict, cfg: dict, moment: float) -> dict:
    record = store["platforms"].setdefault(name, {})
    record["last_attempt_at"] = moment
    if found is None:
        record.update(last_error=error, last_error_at=moment,
                      failures_in_a_row=_count(record.get("failures_in_a_row")) + 1)
        return {"ok": False, "error": error}
    listed = {_key(agent.external_id): agent for agent in found}
    wanted = {agent_id: ref for agent_id, ref in refs.items() if ref[1] == name}
    matched = missing = 0
    for agent_id, (ref, _platform, key) in wanted.items():
        view = store["agents"].setdefault(agent_id, {"external_ref": ref})
        if key in listed:
            matched += 1
            _mark_listed(view, listed[key], moment)
        else:
            missing += _mark_absent(view, cfg["missing_after_runs"], moment)
    claimed = {key for _ref, _platform, key in wanted.values()}
    others = [agent for key, agent in listed.items() if key not in claimed]
    store["unenrolled"][name] = _not_enrolled(_dict(store["unenrolled"].get(name)), others, moment)
    counts = {"listed": len(listed), "matched": matched, "not_enrolled": len(others), "missing": missing}
    record.update(last_success_at=moment, last_error="", last_error_at=None, failures_in_a_row=0,
                  **counts)
    return {"ok": True, "error": "", **counts}


def _described(agent: ObservedAgent) -> dict:
    return {"name": _text(agent.name, _MAX_NAME), "state": agent.state,
            "version": _text(agent.version), "updated_at": _text(agent.updated_at)}


def _mark_listed(view: dict, agent: ObservedAgent, moment: float) -> None:
    view.update(_described(agent), listed=True, last_seen_at=moment, last_checked_at=moment,
                missing_runs=0, missing_on_platform=False, missing_since=None)


def _mark_absent(view: dict, after_runs: int, moment: float) -> bool:
    """Count one successful run without the agent. Returns whether it is now
    marked missing."""
    runs = min(_count(view.get("missing_runs")) + 1, _MAX_COUNT)
    gone = runs >= after_runs
    since = (_stamp(view.get("missing_since")) or moment) if gone else None
    for name in ("name", "state", "version", "updated_at"):
        view.setdefault(name, "")
    view.setdefault("last_seen_at", None)
    view.update(listed=False, last_checked_at=moment, missing_runs=runs,
                missing_on_platform=gone, missing_since=since)
    return gone


def _not_enrolled(before: dict, others: list[ObservedAgent], moment: float) -> dict:
    """This run's not-enrolled list. An agent already on it keeps its first
    sighting; past the cap, the ones known longest are the ones kept, so the
    list does not churn from run to run."""
    entries = {}
    for agent in others:
        first = _stamp(_dict(before.get(agent.external_id)).get("first_seen_at")) or moment
        entries[agent.external_id] = {**_described(agent), "first_seen_at": first,
                                      "last_seen_at": moment}
    ordered = sorted(entries.items(), key=lambda item: (item[1]["first_seen_at"], item[0]))
    return dict(ordered[:_MAX_UNENROLLED])


def _summary(results: dict[str, dict], moment: float) -> dict:
    done = [result for result in results.values() if result["ok"]]
    return {"enabled": True, "ran": True, "at": moment, "platforms": results,
            "succeeded": len(done), "failed": len(results) - len(done),
            "listed": sum(result["listed"] for result in done),
            "matched": sum(result["matched"] for result in done),
            "not_enrolled": sum(result["not_enrolled"] for result in done),
            "missing_on_platform": sum(result["missing"] for result in done)}


def _audit(summary: dict) -> bool:
    """Write the audit row for one check: counts only. A refusal from the
    audit log propagates, so the check is not recorded without its evidence."""
    from .audit import audit_event
    return audit_event("agent_watch_synced", agent="agent_watch",
                       platforms=len(summary["platforms"]), succeeded=summary["succeeded"],
                       failed=summary["failed"], listed=summary["listed"],
                       matched=summary["matched"], not_enrolled=summary["not_enrolled"],
                       missing=summary["missing_on_platform"])


def _tell_drift(runs: dict, refs: dict, moment: float) -> None:
    """Hand each matched agent's fingerprint to drift detection. The hook
    never raises and does nothing while drift detection is off."""
    from . import agent_drift
    for name, (found, _error) in runs.items():
        listed = {_key(agent.external_id): agent for agent in found or []}
        for agent_id, (_ref, platform, key) in refs.items():
            agent = listed.get(key) if platform == name else None
            if agent is not None:
                agent_drift.observe_discovered(
                    agent_id, version_digest=agent.fingerprint,
                    binding_strength=agent.binding_strength, source=name, now=moment)


def status() -> dict:
    """What a UI shows about platform checks: ``{"enabled", "reason",
    "sync_minutes", "missing_after_runs", "problems", "platforms",
    "not_enrolled_count", "missing_count"}``.

    Each configured platform has one row: ``ready`` and ``problem`` (whether
    its settings can be used, and if not why), its last attempt, last success
    and last error, and the counts from its last successful run. Reads only;
    raises :class:`AgentWatchStoreError` when the record cannot be read."""
    cfg = settings()
    store = _load_store()
    active = _active(cfg)
    rows = [_platform_row(name, store) for name in cfg["platforms"]]
    reason = "" if active else (_OFF_REASON if not cfg["enable"] else _GOVERNANCE_OFF_REASON)
    return {"enabled": active, "reason": reason, "sync_minutes": cfg["sync_minutes"],
            "missing_after_runs": cfg["missing_after_runs"], "problems": list(cfg["problems"]),
            "platforms": rows,
            "not_enrolled_count": sum(row["not_enrolled"] for row in rows),
            "missing_count": sum(row["missing"] for row in rows)}


def _platform_row(name: str, store: dict) -> dict:
    record = _dict(store["platforms"].get(name))
    try:
        _build(name)
        problem = ""
    except WatchError as e:
        problem = _safe_message(e)
    error = record.get("last_error")
    return {"name": name, "ready": not problem, "problem": problem,
            "last_attempt_at": _stamp(record.get("last_attempt_at")),
            "last_success_at": _stamp(record.get("last_success_at")),
            "last_error": error if isinstance(error, str) else "",
            "last_error_at": _stamp(record.get("last_error_at")),
            "failures_in_a_row": _count(record.get("failures_in_a_row")),
            "listed": _count(record.get("listed")), "matched": _count(record.get("matched")),
            "not_enrolled": _count(record.get("not_enrolled")),
            "not_enrolled_shown": len(_dict(store["unenrolled"].get(name))),
            "missing": _count(record.get("missing"))}


def unenrolled() -> list[dict]:
    """Agents the configured platforms list that no enrolled agent claims:
    ``{platform, external_id, external_ref, name, state, version, updated_at,
    first_seen_at, last_seen_at}``, by platform and then name. ``external_ref``
    is the value to give an agent at enrollment to claim it. Each platform's
    part is as of its last successful run and holds at most a fixed number of
    entries (``status`` gives the full count). Reads only."""
    store = _load_store()
    rows = []
    for name in settings()["platforms"]:
        for external_id, entry in _dict(store["unenrolled"].get(name)).items():
            state = entry.get("state")
            rows.append({"platform": name, "external_id": external_id,
                         "external_ref": f"{name}:{external_id}",
                         "name": _text(entry.get("name"), _MAX_NAME),
                         "state": state if state in _STATES else "",
                         "version": _text(entry.get("version")),
                         "updated_at": _text(entry.get("updated_at")),
                         "first_seen_at": _stamp(entry.get("first_seen_at")),
                         "last_seen_at": _stamp(entry.get("last_seen_at"))})
    return sorted(rows, key=lambda row: (row["platform"], row["name"].casefold(), row["external_id"]))


def platform_view(agent_id: str) -> dict | None:
    """What the home platform last said about one enrolled agent, or ``None``
    when the agent is not enrolled or has no usable ``external_ref``.

    ``watched`` says whether its platform is being checked at all, ``checked``
    whether a run has looked for it yet, ``listed`` whether the last successful
    run found it (``None`` before the first), and ``missing_on_platform``
    whether it has been absent for ``missing_after_runs`` runs in a row. Reads
    only."""
    ref = _enrolled_refs().get(agent_id)
    if ref is None:
        return None
    external_ref, platform, _match = ref
    cfg = settings()
    view = _dict(_load_store()["agents"].get(agent_id))
    if view.get("external_ref") != external_ref:
        view = {}  # recorded for a different platform agent
    state = view.get("state")
    return {"agent_id": agent_id, "external_ref": external_ref, "platform": platform,
            "external_id": external_ref.partition(":")[2],
            "watched": _active(cfg) and platform in cfg["platforms"],
            "checked": _stamp(view.get("last_checked_at")) is not None,
            "listed": view.get("listed") if isinstance(view.get("listed"), bool) else None,
            "name": _text(view.get("name"), _MAX_NAME),
            "state": state if state in _STATES else "",
            "version": _text(view.get("version")), "updated_at": _text(view.get("updated_at")),
            "last_seen_at": _stamp(view.get("last_seen_at")),
            "last_checked_at": _stamp(view.get("last_checked_at")),
            "missing_runs": _count(view.get("missing_runs")),
            "missing_on_platform": view.get("missing_on_platform") is True,
            "missing_since": _stamp(view.get("missing_since"))}


__all__ = [
    "IMMUTABLE_REVISION",
    "OBSERVED_SNAPSHOT",
    "AgentWatchError",
    "AgentWatchStoreError",
    "Limits",
    "ObservedAgent",
    "Reader",
    "WatchConfigError",
    "WatchError",
    "Watcher",
    "client_credentials_token",
    "enabled",
    "env_name",
    "fingerprint",
    "limits",
    "odata_next",
    "platform_view",
    "register",
    "registered",
    "secret_named",
    "settings",
    "status",
    "store_path",
    "sync",
    "unenrolled",
    "unexpected_answer",
]
