"""Configuration loader for Second Shift.

Reads ``~/.maverick/config.toml`` (or the path set by ``$MAVERICK_CONFIG``).
Supports environment variable interpolation in string values: ``${VAR_NAME}``
is replaced with the env value, or the empty string if unset. Only
operator-owned files interpolate: the dashboard Settings overlay and per-tenant
``config.toml`` files keep ``${VAR}`` literally, because their authors have no
authority to read process secrets.

This is the surface the installer wizard writes to. Users can also edit
the TOML by hand. The kernel falls back to sensible defaults if no
config file exists, so research / dev use doesn't require running the
wizard first.

Schema overview::

    [providers.<name>]
    api_key = "${ANTHROPIC_API_KEY}"
    base_url = "..."  # optional

    [models]
    orchestrator = "anthropic:claude-opus-4-7"
    researcher   = "anthropic:claude-sonnet-4-6"
    # ...

    [budget]
    max_dollars = 5.0
    strict_pricing = true  # false => explicit legacy estimate-only accounting

    [safety]
    profile = "balanced"
"""
from __future__ import annotations

import copy
import errno
import hashlib
import io
import logging
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

# Initialize encryption before a worker resolves sealed dashboard settings.
from . import crypto_at_rest
from ._envparse import coerce_bool
from .file_lock import _windows_extended_path, atomic_read_bytes

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

# Note: do not cache the default at module import time. Both the platform home
# and the documented MAVERICK_HOME override can change in test/embedded
# processes, so resolve them dynamically inside config_path().
DEFAULT_CONFIG_BASENAME = (".maverick", "config.toml")


def _default_config_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / DEFAULT_CONFIG_BASENAME[1]


CONFIG_OVERLAY_ENV = "MAVERICK_CONFIG_OVERLAY"

# Dashboard Settings overlay for config-read settings (provider keys,
# capability/feature toggles). Deep-merged over config.toml on every
# load_config() — always-on at a fixed path next to config.toml — so UI edits
# take effect on the next read without rewriting the user's config.toml. The
# dashboard owns this file (maverick_dashboard.settings_store). Distinct from
# runtime-overrides.toml (denied_tools / models / budget, read via own hooks).
DASHBOARD_OVERRIDES_BASENAME = "dashboard-config.toml"

# Accept lower/mixed-case names too, so a hand-edited config referencing a
# lowercase env var (`${my_token}`) is substituted rather than left as the
# literal `${my_token}`. The docstring promises "${VAR_NAME} is replaced" with
# no case restriction.
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _interp(value: Any) -> Any:
    """Recursively replace ``${VAR}`` with environment values."""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _interp(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interp(v) for v in value]
    return value


def config_path() -> Path:
    override = os.environ.get("MAVERICK_CONFIG")
    if override:
        return Path(override).expanduser()
    # Resolve dynamically so monkeypatch.setenv("HOME", ...) takes effect
    # mid-process — the prior `return DEFAULT_CONFIG_PATH` was evaluated
    # at import time and stayed stale.
    return _default_config_path()


# Parsed-TOML cache keyed by absolute path -> (mtime_ns, size, raw_dict, digest).
# Only the expensive part (file read + TOML parse) is memoized; env-var
# interpolation and the overlay deep-merge still run on every load_config()
# call, so a changed ${VAR} or edited overlay is always reflected. Invalidated
# when the file's mtime OR size changes (a rewrite), or its content digest does
# where st_ctime cannot show a rewrite (see _CTIME_IS_CHANGE_TIME). load_config()
# is on many hot paths (a single inbound A2A delegate triggers ~6-10 full
# parses); on POSIX this removes the redundant I/O + tokenize while preserving
# exact semantics. On Windows the digest reads the file on every check, so only
# the tokenize is saved there (not measured on Windows).
_toml_cache: dict[str, tuple[int, int, dict, bytes | None]] = {}
# General configuration remains fail-soft, but security boundaries need to
# distinguish "file absent" from "present but unreadable/corrupt". Track the
# latter alongside the parsed cache so trust/auth callers can fail closed.
_toml_errors: dict[str, str] = {}
# The dashboard overlay's decryption failures, kept apart from its parse
# errors: a clean parse of a file whose values still cannot be opened must not
# clear them.
_unseal_errors: dict[str, str] = {}
# How many errors have been recorded for each source, ever (never reset). A
# read notes it before touching the file and clears an error only if none was
# recorded meanwhile: a slower read must not erase what a newer one found (a
# replaced file's corruption, a passing permission failure, a key that stopped
# working). It leaves that error for the next read to settle instead.
_toml_gen: dict[str, int] = {}
# A cache entry and its error change together, so a reader never re-reports an
# error another thread has just cleared with a fresh parse, nor the reverse.
# Nothing touches the filesystem while holding it.
_toml_lock = threading.RLock()
# What Path.exists() treats as absent: no such file, or a path through a file.
_ABSENT = (FileNotFoundError, NotADirectoryError)


class _UnreadableTable(dict):
    """A cached source with unreadable content; every hit reports it again."""

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message


# The errors one read itself ran into (see ``single_read``). _toml_errors is
# process-wide: another thread's reset or successful read can clear an entry
# while a read is in flight, so it cannot tell whether *this* read was clean.
_READ_ERRORS: ContextVar[dict[str, str] | None] = ContextVar("maverick_config_read_errors", default=None)


def _record_source_error(key: str, message: str, table: dict[str, str] | None = None) -> None:
    """Report an unreadable source to config_source_errors() and to this read."""
    (_toml_errors if table is None else table)[key] = message
    _toml_gen[key] = _toml_gen.get(key, 0) + 1
    noted = _READ_ERRORS.get()
    if noted is not None:
        noted[key] = message


def _forget_absent(key: str, since: int) -> None:
    """Drop a source found absent, unless an error was recorded for it after
    ``since`` was noted: that came from a read of a file created meanwhile."""
    with _toml_lock:
        if _toml_gen.get(key, 0) == since:
            _toml_cache.pop(key, None)
            _toml_errors.pop(key, None)
            _unseal_errors.pop(key, None)


# Bound the cache so a deployment with many per-tenant config paths
# (~/.maverick/tenants/<t>/config.toml) can't grow it without limit. Entries
# are cheap to rebuild (a stat + parse), so a simple oldest-first cap is enough.
_TOML_CACHE_MAX = 512


def reset_config_cache() -> None:
    """Drop the parsed-TOML and .env-file caches (test hook; prod files rarely
    change)."""
    global _env_last_check
    with _toml_lock:
        _toml_cache.clear()
        _toml_errors.clear()
        _unseal_errors.clear()
    _env_file_cache.clear()
    _env_last_check = None
    kept = _KEPT_READ.get()
    if kept is not None:
        kept.entry = None
    shared = _SINGLE_READ.get()
    if shared is not None:
        shared.noted = {}  # this decision's errors; enclosing ones keep theirs
    while shared is not None:  # this decision and every one it is nested in
        shared.tree = None  # the next read starts again
        shared = shared.outer


# Wizard-persisted secrets: the installer writes every collected key to
# ``~/.maverick/.env`` (next to config.toml) and references it from config
# values as ``${VAR}``. Docker-compose (``env_file``) and the systemd unit
# (``EnvironmentFile=``) inject that file, but a bare pip/CLI install had no
# injector at all, so ``${VAR}`` interpolated to "" and a freshly validated
# key could never reach the runtime (`maverick start` exited 2 right after
# `maverick init` said "Setup complete"). load_config() exports the file
# itself -- an explicitly exported variable always wins; a value the loader
# set itself follows later edits and removals of the file -- memoized by
# mtime+size so a change is a re-read, not a re-load.
# The freshness re-check itself is throttled to once per second: load_config()
# sits on per-row hot paths (e.g. _dec_field on every sealed column read), and
# an unconditional config_path()+stat() per call measurably breached the
# world_read perf SLA. A wizard-written key still lands within a second.
_ENV_FILE_BASENAME = ".env"
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_WIZARD_FORBIDDEN_AUTHORITY_ENV = frozenset({
    "MAVERICK_APPROVER_KEYS", "MAVERICK_REQUIRE_SIGNED_APPROVAL",
    "MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS", "MAVERICK_AUDIT_SIGNING_KEY",
    "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY",
})
_ENV_RECHECK_SECONDS = 1.0
_env_file_cache: dict[str, tuple[int, int, bytes | None]] = {}
# Values this loader put into os.environ, so a later change to .env replaces
# them while an explicitly exported variable still always wins.
_env_file_exported: dict[str, str] = {}
_env_file_lock = threading.Lock()
_env_last_check: float | None = None
# Bound at import: tests that monkeypatch time.monotonic (a process-global
# patch) to drive their OWN timeout logic must not have the values consumed
# by this unrelated guard on every load_config() call.
_monotonic = time.monotonic


def _load_wizard_env() -> None:
    """Throttled wrapper: re-check ``~/.maverick/.env`` at most once per
    :data:`_ENV_RECHECK_SECONDS` (first call always loads)."""
    global _env_last_check
    now = _monotonic()
    if _env_last_check is not None and now - _env_last_check < _ENV_RECHECK_SECONDS:
        return
    _env_last_check = now
    _load_env_file(config_path().parent / _ENV_FILE_BASENAME)


def _load_env_file(path: Path) -> None:
    """Export ``KEY=value`` lines from ``path`` into ``os.environ`` without
    overriding variables that were set by anyone but this loader."""
    with _env_file_lock:  # load_config() runs on many threads
        _load_env_file_locked(path)


def _drop_env_exports(keep: set[str]) -> None:
    """Stop exporting values this loader set for names not in ``keep``, unless
    someone else replaced the value meanwhile."""
    for name in [n for n in _env_file_exported if n not in keep]:
        if os.environ.get(name) == _env_file_exported.pop(name, None):
            os.environ.pop(name, None)


def _load_env_file_locked(path: Path) -> None:
    try:
        st = path.stat()
    except _ABSENT:
        _env_file_cache.pop(str(path), None)
        _drop_env_exports(set())  # .env deleted: what it exported goes too
        return
    except OSError:
        return  # unreadable .env -> keep what was loaded
    key = str(path)
    digest = _content_digest(path, st)  # None (never a hit) when the content is unreadable
    if digest is not None and _env_file_cache.get(key) == (st.st_mtime_ns, st.st_size, digest):
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    _env_file_cache[key] = (st.st_mtime_ns, st.st_size, digest)
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        name = name.strip()
        # Windows environment names ignore case: `maverick_approver_keys`
        # there sets MAVERICK_APPROVER_KEYS, so compare upper-cased names.
        upper = name.upper()
        canonical = ("MAVERICK_" + upper[len("SECOND_SHIFT_"):]
                     if upper.startswith("SECOND_SHIFT_") else upper)
        if not sep or not _ENV_NAME_RE.match(name) or canonical in _WIZARD_FORBIDDEN_AUTHORITY_ENV:
            continue
        value = value.strip()
        # Tolerate hand-edited quoting (systemd EnvironmentFile strips it too).
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if name not in os.environ or os.environ[name] == _env_file_exported.get(name):
            os.environ[name] = value  # first load, or a value this loader set: follow the file
            _env_file_exported[name] = value
        seen.add(name)
    _drop_env_exports(seen)  # a line removed from the file stops being exported


def _read_toml_raw(path: Path) -> dict:
    """Parsed TOML for ``path`` (NO interpolation), memoized by mtime+size.
    Returns ``{}`` for a missing file, and ``{}`` + a warning for a corrupt one."""
    key = str(path)
    since = _toml_gen.get(key, 0)
    try:
        st = path.stat()
    except _ABSENT:
        _forget_absent(key, since)
        return {}  # an absent optional config legitimately means defaults
    except OSError as e:
        with _toml_lock:
            _toml_cache.pop(key, None)
            _record_source_error(key, f"{type(e).__name__}: {e}")
        return {}  # general callers stay fail-soft; security callers inspect health
    # Taken before the parse below: a rewrite after this is seen by the next read.
    digest = _content_digest(path, st)  # None (never a hit) when the content is unreadable
    with _toml_lock:
        cached = _toml_cache.get(key)
        if (digest is not None and cached is not None and cached[0] == st.st_mtime_ns
                and cached[1] == st.st_size and cached[3] == digest):
            if isinstance(cached[2], _UnreadableTable):
                # A reset may have cleared the entry while the corrupt table
                # stayed cached: report it on every hit.
                _record_source_error(key, cached[2].message)
            return cached[2]
    error = None
    cache = True
    try:
        # Private Windows publication retains the verified write handle until
        # rename completes. A reader can see the name before that handle closes.
        with io.BytesIO(atomic_read_bytes(path)) as f:
            raw = tomllib.load(f)
        malformed = [name for name in ("safety", "sandbox")
                     if name in raw and not isinstance(raw[name], dict)]
        if malformed:
            error = ", ".join(f"[{name}] must be a configuration table" for name in malformed)
            logging.getLogger(__name__).warning("invalid %s: %s; treating these sections as empty", path, error)
            normalized = _UnreadableTable(error)
            normalized.update(raw)
            raw = normalized
            for name in malformed:
                raw[name] = {}
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as e:
        # The kernel must tolerate a missing config (returns {} above); a
        # corrupt/unreadable one is the adjacent case. Fail soft to defaults
        # with a warning instead of crashing the agent loop / every
        # get_role_model / get_safety caller on a hand-edited TOML typo.
        logging.getLogger(__name__).warning(
            "ignoring unreadable %s (%s: %s); using defaults",
            path, type(e).__name__, e,
        )
        error = f"{type(e).__name__}: {e}"
        # A sharing/permission failure is not parsed file content. Keep
        # health fail-closed now, but retry the next read even when this
        # complete file's mtime and size have not changed.
        cache = not isinstance(e, OSError)
        raw = _UnreadableTable(error) if cache else {}
    with _toml_lock:
        if error is not None:
            # Its caller gets no policy from this source, so it is always
            # reported, even if the file was replaced meanwhile; a later read
            # of the new file clears it.
            _record_source_error(key, error)
        elif _toml_gen.get(key, 0) != since:
            # Another read found this source unreadable while this one ran,
            # perhaps in a newer file: keep its error and its cache entry.
            return raw
        else:
            _toml_errors.pop(key, None)
        _toml_cache.pop(key, None)
        if not cache:
            return raw
        # Evict oldest entries first when over the cap (dicts preserve
        # insertion order); ``key`` is re-inserted as the newest. An evicted
        # source keeps its error: only a clean read or its absence clears it.
        while len(_toml_cache) >= _TOML_CACHE_MAX:
            _toml_cache.pop(next(iter(_toml_cache)))
        _toml_cache[key] = (st.st_mtime_ns, st.st_size, raw, digest)
    return raw


def _tree_contains_sealed_value(value: object) -> bool:
    """Whether a parsed config tree contains an at-rest ciphertext token.

    Keep this marker-only preflight independent from ``crypto_at_rest`` so an
    ordinary plaintext config load does not import the encryption stack or
    resolve key paths.  ``is_sealed_str`` performs the authenticated structural
    check before any token is actually decrypted below.
    """
    if isinstance(value, str):
        return value.startswith("MVKAR1:")
    if isinstance(value, dict):
        return any(_tree_contains_sealed_value(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_tree_contains_sealed_value(item) for item in value)
    return False


# True while this thread/task is inside ``_unseal_config_tree``. Opening the
# overlay imports the encryption stack and resolves key material, and both can
# resolve the active tenant -> client id -> ``load_config()`` -> this overlay
# again. A nested load only ever needs plaintext keys (``[client] id`` is never
# sealed), so it gets the tree with its tokens left opaque instead of a second
# unseal. Without this guard that is an import cycle that stops every
# production task at boot, and otherwise unbounded recursion. A ContextVar, not a global: concurrent requests on other tasks
# must not observe one another's in-progress unseal.
_UNSEALING: ContextVar[bool] = ContextVar("maverick_config_unsealing", default=False)


def _unseal_config_tree(value: object) -> object:
    """Return a detached config tree with authenticated ciphertext opened.

    Dashboard-managed credentials are deployment-global configuration, so they
    must use the process/deployment key even when a request currently carries a
    tenant context.  Legacy plaintext remains readable; a genuine ciphertext
    that cannot be authenticated fails closed through ``unseal_many_from_str``.
    Each key is resolved once within this read, never cached across config
    reads, so rotations and key-file permission changes remain observable.
    Re-entrant loads (see ``_UNSEALING``) receive the tokens unopened.
    """
    if not _tree_contains_sealed_value(value) or _UNSEALING.get():
        return value
    token = _UNSEALING.set(True)
    try:
        sealed: dict[str, None] = {}

        def collect(item: object) -> None:
            if isinstance(item, str) and crypto_at_rest.is_sealed_str(item):
                sealed[item] = None
            elif isinstance(item, dict):
                for child in item.values():
                    collect(child)
            elif isinstance(item, (list, tuple)):
                for child in item:
                    collect(child)

        def walk(item: object) -> object:
            if isinstance(item, str):
                return opened.get(item, item)
            if isinstance(item, dict):
                return {key: walk(child) for key, child in item.items()}
            if isinstance(item, list):
                return [walk(child) for child in item]
            if isinstance(item, tuple):
                return tuple(walk(child) for child in item)
            return item

        with crypto_at_rest.deployment_key_scope():
            collect(value)
            opened = dict(zip(sealed, crypto_at_rest.unseal_many_from_str(list(sealed)), strict=True))
            return walk(value)
    finally:
        _UNSEALING.reset(token)

# Ends the error recorded for a dashboard overlay that was only partly opened.
# ``operator_preflight`` (``maverick doctor``, Installation health) repeats it.
DASHBOARD_ON_HOLD = ("Settings made in the dashboard are on hold until this file can be opened, "
                     "except stricter safety choices, which stay in force. "
                     "A sandbox that was set up there may not start until then.")


def _stricter_policy_only(tree: dict) -> dict:
    """A dashboard overlay that cannot be opened whole is held entirely.

    Nothing from it applies until the file can be read again; the read error
    is recorded so health reports it and security callers fail closed.
    """
    return {}


def _is_tenant_config_path(path: Path) -> bool:
    from .paths import maverick_home
    try:
        root = maverick_home() / "tenants"
        for candidate, parent in ((Path(os.path.abspath(path)), Path(os.path.abspath(root))),
                                  (Path(path).resolve(strict=False), root.resolve(strict=False))):
            try:
                relative = candidate.relative_to(parent)
            except ValueError:
                continue
            if len(relative.parts) == 2 and relative.name == "config.toml":
                return True
        return False
    except (OSError, RuntimeError):
        return True  # ambiguous paths must not gain env access


def _load_config_file(path: Path, *, interpolate: bool = True) -> dict:
    # Dashboard and tenant authors do not have authority to read process
    # secrets. Only operator-owned configuration layers can interpolate env.
    raw = _read_toml_raw(path)
    # An empty source has no values to interpolate. Avoid resolving filesystem
    # paths on this common hot path; a later nonempty read still checks scope.
    loaded = (_interp(raw) if (raw and interpolate and path.name != DASHBOARD_OVERRIDES_BASENAME
                               and not _is_tenant_config_path(path))
              else copy.deepcopy(raw))
    if path.name == DASHBOARD_OVERRIDES_BASENAME:
        key = str(path)
        since = _toml_gen.get(key, 0)
        partial = False
        try:
            unsealed = _unseal_config_tree(loaded)
        except Exception as exc:
            # An undecryptable sealed overlay value (e.g. after a
            # MAVERICK_ENCRYPTION_KEY rotation leaves dashboard-config.toml
            # sealed under the old key) must NOT crash every config read.
            # Fail soft like a corrupt-TOML source: record the error so
            # config_source_errors() surfaces it (health goes red and security
            # callers fail closed), and put the overlay on hold instead of
            # load_config() raising process-wide. Only its stricter policy
            # values stay in force: dropping those too put every limit the
            # dashboard had tightened back to the installer's value.
            with _toml_lock:
                _record_source_error(
                    key, f"{type(exc).__name__}: {exc}. {DASHBOARD_ON_HOLD}", _unseal_errors)
            unsealed = _stricter_policy_only(loaded)
            partial = True
            logging.getLogger(__name__).warning(
                "dashboard overlay %s could not be decrypted; its settings are on "
                "hold, except stricter safety choices (rotate keys / re-save the "
                "unreadable settings to restore): %s",
                path, exc,
            )
        try:
            from .config_resets import _specs
            for _ in _specs(unsealed):
                pass
        except ValueError as exc:
            # Malformed reset metadata (hand edit, another version) would make
            # every merge raise; drop the overlay and report it like above.
            with _toml_lock:
                _record_source_error(key, f"{type(exc).__name__}: {exc}", _unseal_errors)
            logging.getLogger(__name__).warning(
                "dashboard overlay %s has unreadable reset metadata; dropping it", path,
            )
            return {}
        # A corrected key can recover the same cached TOML without a file
        # edit, and a tree with nothing sealed has nothing left to open. Only a
        # complete read clears a decryption error (a recursive one returns the
        # tokens unopened), only while the tree it opened is still the cached
        # one, and only if no error was recorded while it was being opened.
        if not partial and not _UNSEALING.get():
            with _toml_lock:
                cached = _toml_cache.get(key)
                if cached is not None and cached[2] is raw and _toml_gen.get(key, 0) == since:
                    _unseal_errors.pop(key, None)
        return unsealed  # type: ignore[return-value]
    return loaded


def _deep_merge_config(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


def dashboard_overrides_path() -> Path:
    """Path to the dashboard-owned config overlay (next to config.toml)."""
    return config_path().parent / DASHBOARD_OVERRIDES_BASENAME


def load_governed_records_config() -> dict:
    """Load only sources allowed to select the governed-record backend.

    Tenant overlays must not select a deployment-global persistence plane.
    The deployment-global sources do: config.toml, the dashboard settings
    overlay (written only by a global administrator on Settings > All
    settings), then the operator overlay; environment variables still win in
    the readers. This is :func:`load_global_config`, which never merges a
    tenant overlay.
    """
    return load_global_config()


def governed_records_config_source_errors() -> dict[str, str]:
    """Unreadable sources participating in governed-backend selection."""
    return config_source_errors(include_tenant=False)


def _source_errors(paths: list[Path]) -> dict[str, str]:
    """Return current parse/I/O errors for exactly ``paths``."""
    # Optional overlays are skipped by ``load_config`` once they disappear, so
    # a parse error cached while the file existed would otherwise remain
    # security-significant forever. Clear it only when the filesystem
    # definitively reports that the source is absent. Permission failures and
    # every other I/O error remain fail-closed: they may mean policy exists but
    # cannot be inspected.
    for path in paths:
        key = str(path)
        if key in _toml_errors or key in _unseal_errors:
            since = _toml_gen.get(key, 0)
            try:
                path.stat()
            except _ABSENT:
                _forget_absent(key, since)
            except OSError:
                pass
    errors = {}
    with _toml_lock:
        for path in paths:
            key = str(path)
            message = _toml_errors.get(key)
            if message is None:
                message = _unseal_errors.get(key)
            if message is not None:
                errors[key] = message
    shared = _SINGLE_READ.get()
    if shared is not None and shared.open and shared.noted:
        # A source this decision found unreadable stays reported until the
        # decision ends, even if another thread clears the process-wide entry.
        for path in paths:
            if str(path) in shared.noted:
                errors.setdefault(str(path), shared.noted[str(path)])
    return errors


def config_source_errors(*, include_tenant: bool = True) -> dict[str, str]:
    """Unreadable/corrupt files among the active config sources.

    ``load_config`` intentionally returns defaults for malformed TOML so a typo
    does not crash ordinary model-selection calls. Authentication and trust
    callers inspect this seam immediately after loading and deny remote control
    if policy may have been lost.
    """
    paths = [config_path(), dashboard_overrides_path()]
    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        paths.append(Path(overlay).expanduser())
    if include_tenant:
        tenant = tenant_config_path()
        if tenant is not None:
            paths.append(tenant)
    return _source_errors(paths)


def tenant_config_path() -> Path | None:
    """Path to the active tenant's config overlay, or None in single-tenant mode.

    Resolves to ``~/.maverick/tenants/<tenant>/config.toml`` when a tenant is
    active via an explicit ``set_tenant`` scope or the ``MAVERICK_TENANT`` env
    var, and None otherwise. Deliberately config-free: it reads only the tenant
    ContextVar and env var, NOT ``current_tenant_id()`` (whose client-binding
    branch reads config and would recurse back into ``load_config`` on every
    call -- a hot-path blow-up). A client-bound single deployment already loads
    its own ``config.toml``, so it needs no separate per-tenant overlay.
    """
    try:
        from .paths import _TENANT, _tenant_segment, maverick_home
        tid = _TENANT.get() or os.environ.get("MAVERICK_TENANT", "").strip() or None
        if not tid:
            return None
        path = maverick_home() / "tenants" / _tenant_segment(tid) / "config.toml"
        # Keep ordinary paths stable in config fingerprints and UI context
        # tokens; only deep tenant paths need the Win32 extended spelling.
        if os.name == "nt" and len(os.path.abspath(path)) >= 240:
            return Path(_windows_extended_path(path))
        return path
    except Exception:  # pragma: no cover -- config resolution never blocks a run
        return None


_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def env_flag(name: str) -> bool | None:
    """Parse an env var as a tri-state boolean: ``True``/``False`` for a
    recognized truthy/falsy value, ``None`` when unset or unrecognized. Lets the
    module ``enabled()`` gates share one parser instead of re-spelling the
    ``{"1","true","yes","on"}`` literal set (and its inverse) each time.

    Positive-only callers use ``if env_flag(name): ...``; tri-state callers use
    ``v = env_flag(name); if v is not None: return v``."""
    raw = os.environ.get(name, "").strip().lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    return None


def _strict_config_bool(
    cfg: dict, key: str, default: bool, *, invalid: bool = False,
) -> bool:
    """Read a policy boolean without Python's string-truthiness footgun.

    TOML normally supplies a real bool, but dashboard overlays and callers may
    provide malformed values. Missing uses the documented default; a present
    non-bool uses the caller's fail-closed posture.
    """
    if key not in cfg:
        return bool(default)
    value = cfg.get(key)
    return value if isinstance(value, bool) else bool(invalid)


class _SharedRead:
    __slots__ = ("open", "fresh", "tree", "noted", "outer")

    def __init__(self, fresh: bool, outer: _SharedRead | None) -> None:
        self.open = True
        self.fresh = fresh
        self.tree: dict | None = None
        self.noted: dict[str, str] = {}  # sources this decision found unreadable
        self.outer = outer  # the open decision this one is nested in, if any


# One authorization decision asks a dozen questions of the deployment-global
# configuration (the sign-in methods, the profile, the client binding, the
# dashboard token). Without sharing, each would read the files again and, once
# a secret has been saved from Settings, resolve the at-rest key and decrypt
# it: about 15 reads per decision and 350 per dashboard page. Inside
# ``single_read()`` the
# first clean read is shared and every caller gets its own copy. A read that
# itself ran into an unreadable, corrupt or undecryptable source (recorded in
# ``_READ_ERRORS`` as it happens, never inferred from process-wide state) is
# used once: the next caller reads the files again, exactly as before, and
# config_source_errors() keeps reporting that source until the scope ends.
# reset_config_cache() inside the scope also starts a fresh read.
#
# A plain scope (a page render, a roster audit) joins any open scope. A gate
# opens ``single_read(fresh=True)``: it reads the current files even inside a
# render, joining only another gate's read. No scope outlives its decision.
_SINGLE_READ: ContextVar[_SharedRead | None] = ContextVar("maverick_config_single_read", default=None)


@contextmanager
def single_read(*, fresh: bool = False):
    """Read the deployment-global configuration once for one decision."""
    current = _SINGLE_READ.get()
    if current is not None and current.open and (current.fresh or not fresh):
        yield  # already inside this decision: share its read
        return
    shared = _SharedRead(fresh, current if current is not None and current.open else None)
    token = _SINGLE_READ.set(shared)
    try:
        yield
    finally:
        shared.open = False
        shared.tree = None
        _SINGLE_READ.reset(token)


def _copy_tree(value):
    if isinstance(value, dict):
        return {key: _copy_tree(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_copy_tree(child) for child in value]
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    import copy

    return copy.deepcopy(value)


def load_global_config() -> dict:
    """Load deployment-global config without a per-tenant overlay.

    Repo-global control planes such as DGM must not change authority depending
    on whichever tenant happens to be active in the current request context.
    The dashboard overlay remains writable by the global admin; the optional
    operator-owned config overlay still has higher precedence.
    """
    if _UNSEALING.get():
        return _read_global_config()
    shared = _SINGLE_READ.get()
    if shared is not None and not shared.open:
        shared = None
    if shared is not None and shared.tree is not None:
        return _copy_tree(shared.tree)
    kept = _KEPT_READ.get()
    if shared is None and kept is None:
        return _read_global_config()
    witness = _read_witness() if kept is not None else None
    entry = kept.entry if kept is not None else None
    if (entry is not None and witness is not None and entry[1] == witness
            and _monotonic() - entry[2] <= _KEEP_READ_SECONDS and _same_environment(entry[3])):
        if shared is not None:
            shared.tree = entry[0]
        return _copy_tree(entry[0])
    started = _monotonic()
    environment = _environment() if kept is not None else None
    with _collecting_read_errors() as noted:
        tree = _read_global_config()
    if noted:
        if shared is not None:
            shared.noted.update(noted)
        return tree
    clean = _copy_tree(tree)  # only a read that met no error itself is shared
    if shared is not None and shared.open:
        shared.tree = clean
    if kept is not None and witness is not None:
        kept.entry = (clean, witness, started, environment)
    return tree


class _KeptRead:
    __slots__ = ("entry",)

    def __init__(self) -> None:
        self.entry: tuple[dict, tuple, float, dict] | None = None  # (tree, files, read at, environment)


# Within one request, a decision whose inputs are provably unchanged since the
# request's last clean read uses that read: a page asked about 29 times, each
# reading the files, resolving the at-rest key and decrypting the saved
# secrets again. "Unchanged" is the whole environment and the identity
# (modification and change times, size, device, inode, links, mode, owner, and
# on Windows a content digest, see _CTIME_IS_CHANGE_TIME) of every file a read
# depends on: config.toml, the Settings overlay, the
# operator overlay, the wizard's .env, the at-rest key, its folder and its
# keyring (their own entries, so a link put in their place shows too). A saved
# policy, a rotated key or a changed permission changes one of them and the
# next decision reads again. A Windows ACL change is not visible to stat, so
# a kept read is used for at most _KEEP_READ_SECONDS after the read that fully
# checked the key folder.
_KEEP_READ_SECONDS = 2.0
_KEPT_READ: ContextVar[_KeptRead | None] = ContextVar("maverick_config_kept_read", default=None)


@contextmanager
def kept_reads():
    """Let the decisions of one request share a read while its inputs are unchanged."""
    token = _KEPT_READ.set(_KeptRead())
    try:
        yield
    finally:
        _KEPT_READ.reset(token)


# st_ctime is the change time on POSIX but the creation time on Windows ("Changed
# in version 3.12: st_ctime is deprecated on Windows", os.stat_result). An
# in-place rewrite that restores the modification time and keeps the size then
# changes nothing a stat reports, so there a file's fingerprint also carries a
# SHA-256 of its content (one read of the file per check; not measured on
# Windows). Module-level so a test can patch the platform choice.
_CTIME_IS_CHANGE_TIME = os.name != "nt"


def _content_digest(path: Path, st: os.stat_result) -> bytes | None:
    """The content digest of a regular file where stat cannot show a rewrite,
    ``b""`` (and no file read) everywhere else. None when that content cannot be
    read; the caller must then treat the file as changed, never as unchanged."""
    if _CTIME_IS_CHANGE_TIME or not stat.S_ISREG(st.st_mode):
        return b""
    try:
        # No retry: a denied read only forces a miss, and the read that
        # follows it keeps its own retry.
        return hashlib.sha256(atomic_read_bytes(path, retry_seconds=0.0)).digest()
    except OSError:
        return None


def _file_state(path: Path, *, key_material: bool = False, rechmodded: bool = False) -> object:
    try:
        # The key's own entries, not what they point to: a read refuses a
        # key file or folder replaced by a link, or a hard-linked key file.
        st = os.lstat(path) if key_material else os.stat(path)
    except OSError as e:
        return type(e).__name__
    # Every read re-applies the key folder's private mode, which moves its
    # change time; its mode, owner and link count still show any change.
    changed = None if rechmodded else st.st_ctime_ns
    digest = _content_digest(path, st)
    if digest is None:
        return None  # unreadable content: _read_witness takes no witness
    return (st.st_mtime_ns, changed, st.st_size, st.st_dev, st.st_ino, st.st_nlink,
            st.st_mode, st.st_uid, st.st_gid, digest)


def _environment() -> dict:
    data = getattr(os.environ, "_data", None)
    return dict(data) if isinstance(data, dict) else dict(os.environ)


def _same_environment(kept: dict) -> bool:
    data = getattr(os.environ, "_data", None)
    return (data if isinstance(data, dict) else dict(os.environ)) == kept


def _read_witness() -> tuple | None:
    """The files a deployment-global read depends on, as cheap facts (the
    environment is compared separately, against a copy taken at the read).
    None when they cannot be stated: that read is neither kept nor reused."""
    token = _UNSEALING.set(True)  # resolving the key path may read [client] id once
    try:
        key = crypto_at_rest._key_path()
    except Exception:  # e.g. an invalid [client] id: the read itself reports it
        return None
    finally:
        _UNSEALING.reset(token)
    keyring = key.parent / "at_rest.d"
    base = config_path()
    paths = [base, dashboard_overrides_path(), base.parent / _ENV_FILE_BASENAME, keyring]
    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        paths.append(Path(overlay).expanduser())
    files = tuple(_file_state(path) for path in paths)
    keys = [key]
    if isinstance(files[3], tuple):  # the keyring folder's own state: absent needs no listing
        try:
            with os.scandir(keyring) as entries:
                keys.extend(sorted(keyring / e.name for e in entries if e.name.endswith(".key")))
        except OSError:
            pass
    key_folder = _file_state(key.parent, key_material=True, rechmodded=True)
    key_files = tuple(_file_state(path, key_material=True) for path in keys)
    if key_folder is None or None in files or None in key_files:
        return None  # a file whose content cannot be read is never the same as before
    return (tuple(str(path) for path in [*paths, key.parent, *keys]),
            files, key_folder, key_files,
            crypto_at_rest._FORCE_EXTERNAL_FLEET_KEY.get())


@contextmanager
def _collecting_read_errors():
    noted: dict[str, str] = {}
    token = _READ_ERRORS.set(noted)
    try:
        yield noted
    finally:
        _READ_ERRORS.reset(token)


def _present(path: Path) -> bool:
    """``Path.exists`` for an optional source, except that a symlink loop is
    read so the read reports it: ``exists`` treats a loop as absent and
    silently dropped the policy. A permission error still raises, as callers
    such as the workspace IP allowlist rely on it. One stat answers: every
    configuration load asks about the workspace overlay, and on network storage
    each stat is a round trip."""
    try:
        path.stat()
    except OSError as e:
        if e.errno == errno.ELOOP or getattr(e, "winerror", None) == 1921:
            return True  # a loop
        if e.errno in _ABSENT_ERRNOS or getattr(e, "winerror", None) in _ABSENT_WINERRORS:
            return False
        raise
    except ValueError:
        return False
    return True


# What ``Path.exists`` (Python 3.11 and 3.12) treats as absent rather than raising.
_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF})
_ABSENT_WINERRORS = frozenset({21, 123})  # ERROR_NOT_READY, ERROR_INVALID_NAME


def _read_global_config() -> dict:
    # Wizard-persisted secrets must be in the environment BEFORE interpolation,
    # or every "${ANTHROPIC_API_KEY}" the wizard wrote resolves to "" on a bare
    # pip/CLI install. setdefault semantics: a real export always wins.
    _load_wizard_env()
    cfg = _load_config_file(config_path())
    # Dashboard Settings overlay (always-on, fixed path): UI-edited provider
    # keys / capability+feature toggles merge over config.toml without touching it.
    dash = dashboard_overrides_path()
    if _present(dash):
        from .config_resets import merge_dashboard
        cfg = merge_dashboard(cfg, _load_config_file(dash), _deep_merge_config)
    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        cfg = _deep_merge_config(cfg, _load_config_file(Path(overlay).expanduser()))
    from .runtime_configuration import remember
    remember(cfg, valid=not bool(config_source_errors(include_tenant=False)))
    return cfg


def load_config(path: Path | None = None) -> dict:
    if path is not None:
        return _load_config_file(path)

    cfg = load_global_config()
    # Per-tenant overlay (highest precedence): when a tenant is active, its own
    # config.toml wins, so each client supplies its own provider API keys, model
    # choices and budget without sharing one global credential set. Skipped in
    # single-tenant mode, so the legacy path is byte-for-byte unchanged.
    tcfg = tenant_config_path()
    if tcfg is not None and _present(tcfg):
        shared = _SINGLE_READ.get()
        if shared is None or not shared.open:
            return _merge_tenant(cfg, _load_config_file(tcfg, interpolate=False), tcfg)
        with _collecting_read_errors() as noted:
            tenant = _load_config_file(tcfg, interpolate=False)
        shared.noted.update(noted)  # reported for the rest of the decision
        cfg = _merge_tenant(cfg, tenant, tcfg)
    return cfg


_LOOSENING_LOGGED: set[tuple[str, tuple[str, ...]]] = set()


def _merge_tenant(cfg: dict, tenant: dict, path: Path) -> dict:
    """A tenant overlay may only tighten the policy sections
    (:data:`policy_tighten.TENANT_RULES`), and only keys with a rule; a looser
    value or a key only the organisation sets is ignored, logged once and
    listed by ``maverick doctor`` (:func:`tenant_policy_loosenings`)."""
    merged, ignored, fixed = _tighten_tenant(cfg, tenant)
    marker = (str(path), tuple(ignored), tuple(fixed))
    if (ignored or fixed) and marker not in _LOOSENING_LOGGED:
        _LOOSENING_LOGGED.add(marker)
        logging.getLogger(__name__).warning(
            "workspace settings %s cannot loosen your organisation's policy; ignored: %s; "
            "set by your organisation: %s", path, ", ".join(ignored) or "none", ", ".join(fixed) or "none")
    return merged


def _tighten_tenant(cfg: dict, tenant: dict) -> tuple[dict, list[str], list[str]]:
    """This product runs one workspace; a per-workspace settings file is refused."""
    raise RuntimeError("per-workspace settings files are not supported")


def signing_identity_transition_enabled() -> bool:
    """Whole-installation trust admission requires a healthy global opt-in."""
    try:
        features = load_global_config().get("features") or {}
        return (not config_source_errors(include_tenant=False) and isinstance(features, dict)
                and features.get("signing_identity_transition") is True)
    except Exception:
        return False


def get_features() -> dict:
    """Return the [features] section. These toggle agent-facing behaviors that
    are otherwise always on:

    - ``skills``      inject distilled/installed skills into agent prompts.
                      The MAVERICK_USE_SKILLS env var, when set, overrides this.
    - ``world_model`` inject persisted world-model facts (cross-run memory)
                      into the orchestrator brief. Off = run without prior
                      stored facts; the per-run goal/event/checkpoint store
                      (world.db) still functions regardless.
    - ``streaming``   stream live progress to the terminal during `maverick
                      start`. The MAVERICK_NO_PROGRESS env var / non-TTY output
                      still suppress it.
    - ``pack_editing`` allow editing/overriding domain packs (agents) from the
                      dashboard editor. Off = the editor is read-only and the
                      mutating REST endpoints return 403, so an operator can
                      lock the agent roster in a governed deployment. Writing
                      override TOML on the host is unaffected.
    - ``role_editing`` allow editing the core agent roles (orchestrator, coder,
                      ...) from the dashboard -- a per-tenant system-prompt
                      addendum plus model/effort overrides per role (which win
                      over the global [models]/[effort] config). Off = the roles
                      editor is read-only and its mutating endpoints 403.
    - ``scheduling`` allow arming recurring schedules (cron) from the dashboard
                      workflow builder -- each fire enqueues a ``start_goal`` job
                      run by ``maverick worker``. Off = the schedule endpoints
                      return 403 and the UI hides; the ``maverick schedule`` CLI
                      on the host is unaffected.
    - ``triggers`` allow binding a saved template to an inbound webhook (POST
                      /webhook/run) so an external event runs it as a goal. The
                      inbound route is HMAC-signed exactly like /webhook/start
                      and fails closed without a [webhooks] secret. Off = the
                      /api/v1/triggers editor and the /webhook/run route 404/403
                      and the builder panel hides.

    Draft recovery, record search, Action Center, guided onboarding and workflow
    readiness default on. Workspace recovery, project reviews and outcome
    measurement and employee companions require explicit opt-in. The older
    switches default on. Employee companions expose the enrolled person's task
    status, private companion history controls and optional administrator-permitted
    AI drafts through the existing writer role. Drafts may use eligible retained
    history and currently permitted own-task titles/status; they do not enable
    model tools, task actions, connected sources or learned memory.
    """
    cfg = load_config().get("features", {}) or {}
    return {
        "skills": coerce_bool(cfg.get("skills"), True),
        "world_model": coerce_bool(cfg.get("world_model"), True),
        "streaming": coerce_bool(cfg.get("streaming"), True),
        "pack_editing": coerce_bool(cfg.get("pack_editing"), True),
        "role_editing": coerce_bool(cfg.get("role_editing"), True),
        "draft_recovery": cfg.get("draft_recovery", True) is True,
        "personal_preferences": cfg.get("personal_preferences", True) is True,
        "configuration_profiles": cfg.get("configuration_profiles", True) is True,
        "employee_task_diagnostics": cfg.get("employee_task_diagnostics", True) is True,
        "employee_activation": cfg.get("employee_activation", True) is True,
        "support_center": cfg.get("support_center", True) is True,
        "record_search": cfg.get("record_search", True) is True,
        "workspace_recovery": cfg.get("workspace_recovery", False) is True,
        "signing_identity_transition": signing_identity_transition_enabled(),
        "action_center": cfg.get("action_center", True) is True,
        "guided_onboarding": cfg.get("guided_onboarding", True) is True,
        "workflow_readiness": cfg.get("workflow_readiness", True) is True,
        "project_reviews": cfg.get("project_reviews", False) is True,
        "deliverable_bundles": cfg.get("deliverable_bundles", False) is True,
        "project_workspaces": cfg.get("project_workspaces", False) is True,
        "task_handoffs": cfg.get("task_handoffs", False) is True,
        "human_conversation_handoffs": cfg.get("human_conversation_handoffs", False) is True,
        "outcome_measurement": cfg.get("outcome_measurement", False) is True,
        "commitment_viability": cfg.get("commitment_viability", False) is True,
        "commitment_capability_learning": cfg.get("commitment_capability_learning", False) is True,
        "semantic_rule_reuse": cfg.get("semantic_rule_reuse", False) is True,
        "procedure_interactions": cfg.get("procedure_interactions", False) is True,
        "operational_competence_acquisition": cfg.get("operational_competence_acquisition", False) is True,
        "request_program": cfg.get("request_program", False) is True,
        "commitment_economic_alternatives": cfg.get("commitment_economic_alternatives", False) is True,
        "workflow_step_checks": cfg.get("workflow_step_checks", False) is True,
        "applicability_regions": cfg.get("applicability_regions", False) is True,
        "governed_rule_evolution": cfg.get("governed_rule_evolution", False) is True,
        "recovery_visibility": cfg.get("recovery_visibility", False) is True,
        "private_task_computation": cfg.get("private_task_computation", False) is True,
        "portable_competence": cfg.get("portable_competence", False) is True,
        "work_restructuring": cfg.get("work_restructuring", False) is True,
        "shared_decision_evidence": cfg.get("shared_decision_evidence", False) is True,
        "employee_companions": (
            not config_source_errors() and cfg.get("employee_companions", False) is True
        ),
        "employee_content_access_requests": (
            not config_source_errors() and cfg.get("employee_content_access_requests", False) is True
        ),
        "permission_access_requests": (
            not config_source_errors() and cfg.get("permission_access_requests", False) is True
        ),
        "employee_departures": (
            not config_source_errors() and cfg.get("employee_departures", False) is True
        ),
        "personal_data_controls": (
            not config_source_errors() and cfg.get("personal_data_controls", False) is True
        ),
        "copilot_operations": (not config_source_errors() and cfg.get("copilot_operations", False) is True),
        "scheduling": coerce_bool(cfg.get("scheduling"), True),
        "triggers": coerce_bool(cfg.get("triggers"), True),
    }


# RFC 8176 authentication-method values that mean a second factor was used,
# plus "fido" (Okta/Auth0 emit it for WebAuthn). "pwd", "pin", "kba", "user"
# and the plain biometric hints are single factors and deliberately absent;
# an administrator extends this list in [auth.mfa] amr_values.
DEFAULT_MFA_AMR_VALUES: tuple[str, ...] = (
    "mfa", "mca", "otp", "hwk", "swk", "fido", "pop", "sms", "tel", "sc",
)
# SAML AuthnContextClassRef values that mean a second factor was used.
DEFAULT_MFA_SAML_CONTEXTS: tuple[str, ...] = (
    "http://schemas.microsoft.com/claims/multipleauthn",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
    "urn:okta:loa:2fa:any",
)
DEFAULT_STEP_UP_MINUTES = 15


def _str_list(value: object, default: tuple[str, ...]) -> list[str]:
    if isinstance(value, str):
        value = [part for part in value.split(",")]
    if not isinstance(value, (list, tuple)):
        return list(default)
    return [str(v).strip() for v in value if str(v).strip()]


def get_auth_mfa() -> dict:
    """``[auth.mfa]``: require a second factor at sign-in, and step-up.

    Off by default. ``require`` (``MAVERICK_MFA_REQUIRE``) accepts an OIDC
    session only when the ID token's ``amr`` names one of ``amr_values`` or
    its ``acr`` is in ``acr_values``, and a SAML session only when the
    assertion's authentication context is in ``saml_authn_contexts``.
    ``acr_values`` is also sent on the authorization request.
    ``step_up_minutes`` (``MAVERICK_MFA_STEP_UP_MINUTES``) is how recent that
    second factor must be for a sensitive action while ``require`` is on.
    A workspace's own config.toml overlays these keys for its members.
    """
    cfg = (load_config().get("auth") or {}).get("mfa") or {}
    if not isinstance(cfg, dict):
        cfg = {}
    require = env_flag("MAVERICK_MFA_REQUIRE")
    if require is None:
        # A present non-bool is uncertainty about a security policy: on.
        require = _strict_config_bool(cfg, "require", False, invalid=True)
    minutes_raw: object = os.environ.get("MAVERICK_MFA_STEP_UP_MINUTES") or cfg.get(
        "step_up_minutes", DEFAULT_STEP_UP_MINUTES)
    try:
        minutes = int(float(str(minutes_raw)))
    except (TypeError, ValueError, OverflowError):  # OverflowError: ``inf`` / ``1e999``
        # An unusable window is invalid like any other: the documented default
        # applies. Raising here would read as "policy unreadable" downstream and
        # reject every named sign-in as missing a second factor.
        minutes = DEFAULT_STEP_UP_MINUTES
    if isinstance(minutes_raw, bool) or minutes < 1:
        minutes = DEFAULT_STEP_UP_MINUTES
    return {
        "require": bool(require),
        "step_up_minutes": minutes,
        "amr_values": _str_list(cfg.get("amr_values"), DEFAULT_MFA_AMR_VALUES),
        "acr_values": _str_list(cfg.get("acr_values"), ()),
        "saml_authn_contexts": _str_list(
            cfg.get("saml_authn_contexts"), DEFAULT_MFA_SAML_CONTEXTS),
    }


def get_auth_sessions() -> dict:
    """Installation-wide browser limits and ended-session retention."""
    if config_source_errors(include_tenant=False):
        raise ValueError("Sign-in settings cannot be read.")
    loaded = load_global_config()
    if config_source_errors(include_tenant=False):  # the load itself may have found it
        raise ValueError("Sign-in settings cannot be read.")
    authentication = loaded.get("auth", {})
    if not isinstance(authentication, dict):
        raise ValueError("Sign-in settings must contain named choices.")
    cfg = authentication.get("sessions", {})
    if not isinstance(cfg, dict):
        raise ValueError("Sign-in settings must contain named choices.")
    raw = cfg.get("retention_days", 30)
    try:
        days = int(raw) if not isinstance(raw, bool) else 30
    except (TypeError, ValueError, OverflowError):
        days = 30
    limits = {}
    for name, maximum in (("company_hours", 168), ("idle_minutes", 1440)):
        value = cfg.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise ValueError(f"auth.sessions.{name} must be an integer from zero to {maximum}")
        limits[name] = value
    return {"retention_days": max(1, min(days, 3650)), **limits}


_EKKO_DEFAULT_BLOCKED_APPS = (
    "email",
    "outlook",
    "gmail",
    "chat",
    "teams",
    "slack",
    "crm",
    "salesforce",
    "erp",
    "sap",
    "database",
)


def get_ekko() -> dict:
    """Return the client-controlled ``[ekko]`` work-discovery policy.

    Ekko observes *application metadata*, not screen, clipboard, keystroke, or
    document content.  It is deliberately OFF until a client enrolls a device,
    and it does not inherit the default-on governed-learning posture.  An empty
    ``allowed_apps`` list is deny-all: the deployment must authorize apps
    before a device can enroll. ``blocked_apps`` always wins.

    ``MAVERICK_EKKO`` is the only environment override.  It controls only the
    master switch; an invalid value fails closed instead of falling through to
    a potentially-enabled config file. Provider egress is reserved and forced
    off because this release has no reviewed network path for Ekko data.
    """
    cfg = load_config().get("ekko", {}) or {}
    if not isinstance(cfg, dict):
        cfg = {}

    def _bounded_int(key: str, default: int, low: int, high: int) -> int:
        try:
            raw = cfg.get(key, default)
            # Do not silently treat TOML booleans as integers.
            value = default if isinstance(raw, bool) else int(raw)
        except (TypeError, ValueError, OverflowError):
            value = default
        return max(low, min(high, value))

    def _app_list(key: str, default: tuple[str, ...] = ()) -> list[str]:
        from .work_discovery import KNOWN_APPS

        raw = cfg.get(key, list(default))
        if not isinstance(raw, (list, tuple)):
            return list(default)
        result: list[str] = []
        seen: set[str] = set()
        invalid = False
        for item in raw[:128]:
            if not isinstance(item, str):
                invalid = True
                continue
            name = item.strip().casefold()
            if (
                not name
                or len(name) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or name not in KNOWN_APPS
            ):
                invalid = True
                continue
            if name not in seen:
                seen.add(name)
                result.append(name)
        # A misspelled sensitive-app blocklist must not silently erase the
        # defense-in-depth defaults. The caller also unions this result with
        # the immutable sensitive-app floor, including for an explicit [].
        if key == "blocked_apps" and raw and invalid:
            return list(default)
        return result

    retention_days = _bounded_int("retention_days", 14, 2, 30)
    min_distinct_days = min(
        retention_days,
        _bounded_int("min_distinct_days", 2, 2, 30),
    )
    capture_level = cfg.get("capture_level", "application_metadata")
    if capture_level not in {"application_metadata", "guided"}:
        capture_level = "application_metadata"

    enabled = _strict_config_bool(cfg, "enable", False)
    if "MAVERICK_EKKO" in os.environ:
        # Invalid values are not "unset": fail closed even if config says on.
        enabled = env_flag("MAVERICK_EKKO") is True

    configured_blocks = _app_list("blocked_apps", _EKKO_DEFAULT_BLOCKED_APPS)
    blocked_apps = list(dict.fromkeys(
        (*_EKKO_DEFAULT_BLOCKED_APPS, *configured_blocks)
    ))
    blocked = set(blocked_apps)
    allowed_apps = [
        name for name in _app_list("allowed_apps") if name not in blocked
    ]
    return {
        "enable": enabled,
        "planning_enabled": _strict_config_bool(cfg, "planning_enabled", False),
        "build_enabled": _strict_config_bool(cfg, "build_enabled", False),
        "retention_days": retention_days,
        "enrollment_days": _bounded_int("enrollment_days", 30, 1, 90),
        "min_occurrences": _bounded_int("min_occurrences", 3, 2, 100),
        "min_distinct_days": min_distinct_days,
        "poll_interval_seconds": _bounded_int(
            "poll_interval_seconds", 5, 1, 300,
        ),
        "capture_level": capture_level,
        "allowed_apps": allowed_apps,
        "blocked_apps": blocked_apps,
        # Reserved for a future separately-audited summary path. The current
        # local discovery implementation has no provider path, so config may
        # not arm one pre-emptively.
        "provider_egress": False,
    }


def get_ekko_policy(*, allowed_apps: list[str] | tuple[str, ...] | None = None):
    """Build Ekko's canonical :class:`CapturePolicy` under the admin ceiling.

    ``[ekko].allowed_apps`` is the deployment-wide ceiling. Enrollment may
    narrow it, never widen it; omitting ``allowed_apps`` selects the whole
    configured ceiling. Unknown canonical IDs are rejected so CLI, dashboard,
    and daemon compute the exact same policy fingerprint.
    """
    from .work_discovery import (
        ACTION_KINDS,
        APPLICATION_METADATA_ACTIONS,
        APPLICATION_METADATA_OBJECT_TYPES,
        GUIDED_OBJECT_KINDS,
        KNOWN_APPS,
        CapturePolicy,
    )

    cfg = get_ekko()
    ceiling = frozenset(cfg["allowed_apps"])
    if allowed_apps is None:
        selected = ceiling
    else:
        normalized = frozenset(str(app).strip().casefold() for app in allowed_apps)
        unknown = normalized - KNOWN_APPS
        if unknown:
            raise ValueError(
                "unknown canonical application IDs: " + ", ".join(sorted(unknown))
            )
        outside = normalized - ceiling
        if outside:
            raise ValueError(
                "applications exceed [ekko].allowed_apps ceiling: "
                + ", ".join(sorted(outside))
            )
        selected = normalized
    policy = CapturePolicy(
        enabled=cfg["enable"],
        capture_level=cfg["capture_level"],
        allowed_apps=selected,
        blocked_apps=frozenset(cfg["blocked_apps"]),
        allowed_actions=(
            ACTION_KINDS
            if cfg["capture_level"] == "guided"
            else APPLICATION_METADATA_ACTIONS
        ),
        allowed_object_types=(
            GUIDED_OBJECT_KINDS
            if cfg["capture_level"] == "guided"
            else APPLICATION_METADATA_OBJECT_TYPES
        ),
        retention_days=cfg["retention_days"],
        min_occurrences=cfg["min_occurrences"],
        min_distinct_days=cfg["min_distinct_days"],
        poll_interval_seconds=cfg["poll_interval_seconds"],
        provider_egress=False,
    )
    policy.require_valid(require_enabled=True)
    return policy


def validate_ekko_policy_ceiling(policy) -> None:
    """Fail closed when an enrolled policy no longer fits current config.

    App selection may be a strict subset. Every other capture/retention field
    and the sensitive-app blocklist must still match the current admin policy;
    config changes therefore require an explicit re-enrollment.
    """
    from .work_discovery import CapturePolicy

    if not isinstance(policy, CapturePolicy):
        raise TypeError("policy must be a CapturePolicy")
    ceiling = get_ekko_policy()
    if not policy.allowed_apps <= ceiling.allowed_apps:
        raise ValueError("enrolled application scope exceeds the current config ceiling")
    comparable = (
        "enabled",
        "capture_level",
        "blocked_apps",
        "allowed_actions",
        "allowed_object_types",
        "retention_days",
        "min_occurrences",
        "min_distinct_days",
        "poll_interval_seconds",
        "provider_egress",
    )
    if any(getattr(policy, name) != getattr(ceiling, name) for name in comparable):
        raise ValueError("Ekko policy config changed; re-enrollment is required")


def get_external_agents() -> dict:
    """Return the ``[external_agents]`` section (bring-your-own-agent gateway:
    enrollment, run ingest onto the Operating Record, pre-action screening).
    OFF by default: admitting foreign runtimes is an explicit trust decision,
    made per-agent in the trust registry once the plane is on. Also honored
    via ``MAVERICK_EXTERNAL_AGENTS=1``."""
    cfg = load_config().get("external_agents", {})
    raw = cfg.get("connectors", [])
    if isinstance(raw, str):
        raw = raw.split(",")
    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        # Signed-identity enforcement on the gateway: when on, an agent
        # enrolled with a strong credential (pinned Ed25519 pubkey or JWT
        # issuer) may no longer authenticate with its minted bearer alone —
        # it must present that credential. Agents holding only bearers are
        # unaffected. Strict bool; a malformed value engages the refusal
        # (fail closed — this is a tightening switch).
        "require_signed": _strict_config_bool(
            cfg, "require_signed", False, invalid=True),
        # Governed-REST connectors external agents may EXECUTE through (the
        # enforcement tier above screening). Empty = screen-only; naming one
        # here is the operator's explicit decision to let foreign agents act
        # through Second Shift's egress-guarded, receipted connector path.
        "connectors": [str(p).strip().lower() for p in raw if str(p).strip()],
        # Step-up re-auth on credential minting: when on, ``mint_token`` parks
        # a world approval (dual-control quorum at "high" risk) and refuses to
        # mint until a decision-maker approves; each approval mints exactly
        # one credential. Strict bool; a malformed value engages the gate
        # (fail closed — this is a tightening switch).
        "mint_approval": _strict_config_bool(
            cfg, "mint_approval", False, invalid=True),
        # Whether a person deciding a parked action is shown the agent's own
        # description of it (shortened, secrets removed). Off keeps the
        # request content-free: agent, action name and risk only.
        "show_request_detail": coerce_bool(cfg.get("show_request_detail"), True),
    }


def get_control_plane() -> dict:
    """Return the ``[control_plane]`` section (the Agent Control Plane).

    ``enable`` arms the mutating verbs of ``maverick.agent_control_plane``
    (suspend / resume / contain / release / attenuate / halt) on the dashboard
    console and ``maverick control-plane``; the roster, status and ledger
    reads work regardless. Off by default so a deployment that never opted in
    cannot have a principal revoked from a stray click. Env override:
    ``MAVERICK_CONTROL_PLANE=1`` enables.
    """
    import os
    cfg = load_config().get("control_plane", {}) or {}
    enable = coerce_bool(cfg.get("enable"), False)
    if os.environ.get("MAVERICK_CONTROL_PLANE", "").strip() == "1":
        enable = True
    return {"enable": enable}
