"""Helpers shared by the dashboard's ``app`` and ``api`` modules.

These four symbols lived as verbatim copies in both ``app`` and ``api``.
The duplication was deliberate -- ``app`` imports ``api`` at module load,
so the reverse import would cycle, and the old ``_world`` docstrings said
as much. A third module that imports neither removes the copies without
reintroducing the cycle; both modules ``from ._shared import`` these.
"""
from __future__ import annotations

import os
from typing import Any

# One process-wide WorldModel cache keyed by absolute DB path (was a
# separate dict per module). Tests clear it via ``<module>._world_cache``.
_world_cache: dict[str, Any] = {}


def dashboard_token() -> str:
    """The server's access token: ``MAVERICK_DASHBOARD_TOKEN``, else the sealed
    ``[dashboard] token`` a global administrator set on Settings > All
    settings (installation-wide config only: a workspace's own settings can
    never supply it). Empty when neither is set."""
    env = os.environ.get("MAVERICK_DASHBOARD_TOKEN", "")
    if env:
        return env
    from ._request_memo import memoized

    # Several middlewares ask on every request, on the event loop; one answer
    # per request (a gate under fresh_configuration() still reads the files).
    return memoized("dashboard_token", _saved_dashboard_token)


def _saved_dashboard_token() -> str:
    try:
        from maverick.config import load_global_config

        table = (load_global_config() or {}).get("dashboard") or {}
    except Exception:  # unreadable settings: no configured token (auth fails closed)
        return ""
    value = table.get("token") if isinstance(table, dict) else None
    return value.strip() if isinstance(value, str) else ""


def _world():
    """Return a per-DB-path cached WorldModel.

    Opening a new WorldModel on every request re-runs the PRAGMAs and the
    schema-migration check, leaks the connection (no close()), and
    serialises the asyncio loop because sqlite3 is sync. Cache by absolute
    DB path so test fixtures that monkeypatch ``DEFAULT_DB`` to a fresh
    ``tmp_path`` still get an isolated WorldModel per test.
    """
    # Client binding: when the deployment is bound to a client, the dashboard
    # reads/writes that client's isolated world DB (under tenants/<client>/),
    # never the shared root. Unbound (legacy / tests that monkeypatch
    # DEFAULT_DB) keeps the prior DEFAULT_DB path exactly.
    #
    # Backend selection (split-brain fix): when the deployment opts into Postgres
    # ([world_model] backend = "postgres" / MAVERICK_WORLD_BACKEND=postgres), the
    # dashboard must read/write the SAME Postgres the runner, channel server and
    # gRPC API use; always opening SQLite would leave a Postgres deployment's
    # dashboard reading a stale local world.db. Checked before
    # the tenant floor because Postgres isolates by tenant_id at query time, not
    # by a per-tenant file. open_postgres_world() builds a fresh connection per
    # call, so cache the one backend for the process under a fixed key.
    from maverick.world_model_backends import is_postgres_configured
    if is_postgres_configured():
        cached = _world_cache.get("__postgres__")
        if cached is None:
            from maverick.world_model import open_world
            cached = open_world()  # also enforces the at-rest fail-closed guard
            _world_cache["__postgres__"] = cached
        return cached
    from maverick.paths import current_tenant_id
    tid = current_tenant_id()
    if tid:
        from maverick.world_model import world_for_tenant
        return world_for_tenant(tid)
    from maverick.world_model import default_db_path, open_world
    path = default_db_path()
    key = str(path)
    cached = _world_cache.get(key)
    if cached is None:
        # Preserve DEFAULT_DB override ownership semantics: open_world() knows
        # whether this is Second Shift's managed default or a caller-owned path.
        cached = open_world()
        _world_cache[key] = cached
    return cached
