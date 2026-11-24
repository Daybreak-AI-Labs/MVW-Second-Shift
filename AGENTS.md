# Working in this repository

Guidance for coding agents (and people) changing Second Shift. Read it before
the first change.

## The product

Second Shift governs AI agents that run on other platforms (Microsoft Copilot
Studio, Microsoft 365 Copilot, Microsoft Foundry, ServiceNow, Workday and
custom agents), builds new agents (the agent factory) and finds repeated work
worth automating (Ekko). It runs in the customer's Azure tenant, signs people
in with Microsoft Entra ID and keeps its records in PostgreSQL.

- `maverick/`: the core (governance, drift, platform checks, Ekko, storage,
  audit). The package name is internal; do not rename it.
- `maverick_dashboard/`: the web app (FastAPI, Jinja templates, plain
  JavaScript in `static/`). Entry point: `python -m maverick_dashboard.app`.
- `tests/core`, `tests/dashboard`: carried tests. `tests/new`: tests for code
  written for this product. New tests go in `tests/new`.
- `docs/`: notes for administrators. Keep them in step with behaviour.

## Commands

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[postgres,dev]'
.venv/bin/python -m pytest -q -n auto --dist loadfile          # whole suite
MAVERICK_TEST_SECURE_DEFAULT=1 .venv/bin/python -m pytest -q -n auto --dist loadfile   # production posture
.venv/bin/python -m ruff check .                               # must pass
```

Run tests as `python -m pytest`, never a bare `pytest`. With
`MAVERICK_PG_DSN` set to a PostgreSQL login that may create databases, the
Postgres tests run too. A change is finished when the suite passes in both
postures and lint is clean.

## Rules

1. **Name.** Everything a person can read (pages, messages, emails, alerts,
   docs, file names they download, values they paste) says "Second Shift".
   Never "Lightwork", "Daybreak" or "Maverick". Settings may be written
   `SECOND_SHIFT_X`; the code reads them as `MAVERICK_X`.
2. **Plain language.** Messages say what happened and what to do next, in
   words an administrator or an employee understands. No internal codes in
   messages.
3. **Fail closed.** If a permission, a setting, a record or the audit log
   cannot be read, refuse. Never treat "unknown" as "allowed".
4. **Secrets.** Settings hold the name of an environment variable, never the
   secret. A secret, token, key or webhook address never appears in a log, a
   response, an error, an audit entry or a saved record.
5. **Outbound calls** go through `maverick.tools._ssrf.safe_client` with a
   timeout and a size bound. No caller-supplied URLs for server-side requests.
6. **Permissions.** `admin` (settings, enrollment, keys), `audit` (read the
   trail), `operate` (day-to-day; implies `approve` and `respond`), `approve`
   (decide waiting requests), `respond` (pause, resume, limit agents, the
   emergency stop), `view`. Every new route checks one with
   `auth.require_permission`. Mutating routes from the browser also pass the
   same-origin check.
7. **Tests first** for validation, parsing and authorization. Web tests use
   `TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})`
   and point `world_model.DEFAULT_DB` at `tmp_path`. pytest-asyncio is strict:
   async tests need `@pytest.mark.asyncio`.
8. **Dependencies.** No new third-party package for the server without asking.
9. **Style.** Small, surgical changes that match the code around them. Module
   docstrings say what the module does and what it does not do. No speculative
   abstractions.
10. **Pages** use the shared stylesheet and helpers in `static/` (`mvFetchJSON`,
    `mvToast`, `mvConfirm`, `mvForm`), escape everything that came from a user,
    an agent or a platform, and work without a page reload where it matters.
