# Work for Codex on Second Shift, round 2

Do the jobs below in order, one branch and one pull request per job, each against `claude/friendly-shannon-e8jwva`. Start each job from the latest `claude/friendly-shannon-e8jwva`. Do not wait for a reply between jobs.

Since this list was written, the branch gained: a settings page in progress (`/settings`), factory exports in progress (they add a `kind` field to `/api/v1/external/screen` refusals and a `declared` field to `/runs/start`, and may update `kits/`), a My agents page and weekly owner note, an Entra directory module, and a model register. Fetch before each job.

Each job: start from the latest `claude/friendly-shannon-e8jwva`, read `AGENTS.md`, work on its own branch, open a pull request against `claude/friendly-shannon-e8jwva`. Other builders are changing `maverick_dashboard/app.py`, `maverick_dashboard/auth.py`, `maverick/external_agents.py` and the templates at the same time: keep edits to those files small and say in the pull request exactly which lines you touched. Run the whole suite in both postures (`.venv/bin/python -m pytest -q -n auto --dist loadfile`, and again with `MAVERICK_TEST_SECURE_DEFAULT=1`) and `ruff check .` before opening the pull request.

---

## 1. Fix the seven findings in `docs/review/security-review.md`

Branch `codex/security-fixes`. Tests first for each: a test that fails today and passes after the fix.

1. **Sign-in role stays after its mapping changes.** Keep the originating app-role values in the signed session, not only the mapped role, and on every request recompute the role from those values and the current `[auth.oidc.role_map]`. A removed or changed mapping takes effect at once for open sessions. Add a setting for the longest a browser session may last (default 8 hours), and document in `docs/sign-in-roles.md` that removing someone's Entra app role takes effect at their next sign-in or when that limit ends.
2. **Signed requests do not cover method and address.** Add a version 2 of both signing formats (HMAC and Ed25519) that covers the method, path, query, the deployment's public origin, the agent id, time, nonce and body digest. Accept version 1 only when a setting allows it (default: not allowed for newly enrolled agents; allowed for agents enrolled before the change, with a warning shown on the agent page). Keep the replay ledger. Update the TypeScript and .NET kits in `kits/` if they sign requests.
3. **Unauthenticated clients can hold the body readers.** Refuse a request to `/api/v1/external/` that carries no credential of a supported form before its body is read. Give unauthenticated reads their own small concurrency limit, separate from admitted agents. Document edge limits to set in Azure in `docs/deploy-azure.md`.
4. **Same-origin check ignores the scheme.** Compare full origins (scheme, host, port) against the configured public origin (`SECOND_SHIFT_PUBLIC_URL`) when set, or the request's own origin when not. One shared function for browser writes and logout.
5. **Validation errors echo input.** For `/api/v1/external/`, `/copilot-studio/` and any Teams bot path, return validation errors built from field names and fixed messages only: never the submitted value, its context or input-derived path parts.
6. **SMTP without TLS.** Refuse to authenticate or send over a connection without verified TLS, except to a relay on the same machine with no username set. Plain words in the alert status page when this blocks delivery.
7. **Break-glass token audit is sampled.** Record every request made with the break-glass token that changes something, and refuse it when that record cannot be written. Reads may stay sampled. Document the change.

---

## 2. ServiceNow incidents

Branch `codex/servicenow-incidents`. New module `maverick/servicenow_incidents.py`, settings `[servicenow_incidents]`, tests, `docs/servicenow-incidents.md`.

- Open an incident in the customer's ServiceNow instance when Second Shift blocks an agent for rule breaks, raises a high-severity drift finding, marks an agent missing from its platform, or someone turns on the emergency stop. Update it when the finding is acknowledged or the agent is released, and resolve it then.
- One incident per agent and cause (a correlation id that Second Shift keeps), never duplicates on retry. Short description and description in plain words; no secrets, no agent prompts or outputs.
- OAuth 2.0 client credentials to the instance (client id and secret by environment variable name), the instance address validated as a ServiceNow address, all calls through `maverick.tools._ssrf.safe_client`. A ServiceNow outage never blocks the governance action that caused the incident; failed calls are retried with a bounded back-off and shown on the alert status page.
- Hook into the place these events are already announced (`maverick/ops_alert.py` and its callers). Keep that change small.
- Confirm every ServiceNow request, field name, state value (resolved, closed), close code and required role from ServiceNow's own documentation and cite each URL in the code and docs. Earlier research could not confirm any of them, so say plainly which you could and could not confirm.

---

## 3. Ask Second Shift from Microsoft 365 Copilot

Branch `codex/m365-copilot`. New read-only API module, a `m365-copilot/` folder for the app package, tests, `docs/m365-copilot.md`.

- Read-only endpoints shaped for questions people ask in Copilot: agents that changed this week (with the "what changed" summary), requests waiting for a decision, agents blocked or over budget, agents found on platforms but not added, and an agent's status by name. Each answers only what the caller's role allows (the same permission checks as the pages). No endpoint changes anything.
- Authentication with the caller's own Entra token (Second Shift already accepts identity-provider bearer tokens when OpenID Connect is on; read `maverick_dashboard/auth.py`). No API keys.
- An OpenAPI description of just these endpoints, and a declarative agent plus API plugin package using the current manifest versions in Microsoft's documentation (cite them), with single sign-on through Entra.
- `docs/m365-copilot.md`: deployment through the Microsoft 365 admin center, the licences users need, preview or general-availability status of each piece, and what was not tested in a real tenant.

---

## 4. Spend and value reporting (optional, if there is room)

Branch `codex/spend-reporting`. New page `/spend`, its API, tests, a short doc.

- Spend by agent, department, platform and month, from the run reports Second Shift already records; each agent's spend against its limit; a simple forecast of which agents will pass their limit this month at the current rate; export of the same tables as CSV.
- `view` permission to read; the page in the shared design and in the sidebar.
