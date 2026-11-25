# Work for Codex on Second Shift, round 3

Codex now does the building, the reviewing and the merging; Claude only reviews a batch of
security-sensitive changes later. Read "Working without Claude" at the end before job 1.

Each job: start from the latest `claude/friendly-shannon-e8jwva`, read `AGENTS.md`, work on its
own branch, open a pull request against `claude/friendly-shannon-e8jwva`. Before opening it,
run the whole suite in both postures and lint, as `AGENTS.md` says, and say in the pull request
which commands you ran and their final lines. Confirm every Microsoft or Azure fact (resource
types and API versions, Graph permission names, CLI flags) from Microsoft's own documentation and
cite the URL next to it; say plainly what you could not confirm. Nothing here has a live Azure
subscription or tenant to test against: write it so it can be checked without one, and list what
still needs a real tenant. Do not add attribution or co-author lines to commits or pull requests.
Keep this file up to date: tick off each job as it merges, and delete the file only when
every job is merged.

The app runs as one copy for everyone (one Container App replica, one process). Do not design for
several copies.

---

## 1. Continuous integration (merged in PR #8)

Branch `codex/ci`. `.github/workflows/ci.yml`, on pull requests and pushes to
`claude/friendly-shannon-e8jwva`:

- `ruff check .`;
- the whole suite in the default posture, and again with `MAVERICK_TEST_SECURE_DEFAULT=1` and
  `MAVERICK_PG_DSN` pointing at a PostgreSQL 16 service container whose login may create
  databases (the Postgres tests create and drop their own databases);
- `runtime/tests` (the runtime has its own `pyproject.toml`; install `./runtime[office]`);
- the TypeScript kit (`cd kits/typescript && npm ci && npm test`) and the .NET kit
  (`dotnet test kits/dotnet/tests`);
- `docker build -f deploy/azure/Dockerfile .` (build only, no push). It has never been built;
  fix what the build finds and say what you changed;
- `az bicep build` (or the Bicep CLI) for every file in `deploy/azure/`.

Pin every third-party action to a full commit SHA. No secrets in the workflow. Python 3.12.
If a test fails only in CI, find out why before changing it; never skip or loosen a test to get
green.

## 2. Register Second Shift in Entra ID with one script (merged in PR #9)

Branch `codex/entra-registration`. `deploy/azure/register-entra.sh` (Azure CLI and `az rest`
to Microsoft Graph), safe to run again, that creates or updates the single-tenant app
registration the kit needs:

- the web redirect `<public origin>/auth/callback`;
- app roles whose values match `docs/sign-in-roles.md` and the `[auth.oidc.role_map]` the kit
  writes (admin, governance lead, operator, approver, responder, auditor, viewer);
- the Microsoft Graph application permissions that `docs/entra-directory.md`,
  `docs/platform-checks.md` and `docs/deploy-azure.md` list, each behind a flag so an operator
  asks only for what they turn on;
- for Microsoft 365 Copilot (`docs/m365-copilot.md`): the delegated scope
  `SecondShift.Copilot.Read`, `requestedAccessTokenVersion = 2`, the Teams consent redirect, and
  the Microsoft Enterprise token store client pre-authorised for that scope.

It never grants admin consent itself: it prints the consent link for an administrator. It never
prints or stores a secret; a client secret, if the kit needs one, goes straight into Key Vault.
It prints the ids the rest of the kit asks for. Update `docs/deploy-azure.md` section 3 to use it.

## 3. The Teams bot in the Azure kit (merged in PR #10)

Branch `codex/teams-bot-azure`. Add the Azure Bot resource to the Bicep kit: single-tenant,
messaging endpoint `<public origin>/webhook/teams` (`maverick_dashboard/teams_bot.py`), the
Microsoft Teams channel enabled, using the app identity `docs/teams-approvals.md` describes.
Behind a parameter so a deployment without Teams creates nothing. Update
`docs/teams-approvals.md` and `docs/deploy-azure.md` with how to build the Teams app package
(`teams-app/build_package.py` already exists) and upload it in the Teams admin center.

## 4. Watch the deployment itself (merged in PR #11)

Branch `codex/azure-monitoring`. Add to the Bicep kit an action group (an operator email
address as a parameter) and alert rules for: the app restarting or not ready, a rise in 5xx
responses, the PostgreSQL server's CPU, storage and failed connections, the Azure Files share
nearing its quota, and log queries on the app's own warnings that people would otherwise miss
(alerts that cannot reach anyone, "saved record unavailable", the audit record being
unavailable). Plain-language alert names and descriptions. Document each alert and what to do
when it fires in `docs/deploy-azure.md`.

## 5. A check to run right after each deployment (merged in PR #12)

Branch `codex/post-deploy-check`. `deploy/azure/check-deployment.sh <public origin>`: the
health endpoints answer; sign-in redirects to the tenant's Entra login; the public agent schema
is served; a request to the agent gateway without a key is refused before its body is read; an
unsigned request to the Teams webhook is refused. With an administrator credential from Key
Vault (optional), it also enrolls a throwaway agent, has it screen one harmless action with its
key, checks a wrong key is refused, and removes the agent again. Prints a pass/fail line per
check in plain words and exits non-zero on any failure. Never prints a key or token.

## 6. How many people one copy can serve (merged in PR #13)

Branch `codex/load-check`. A developer tool (not a server dependency) under `tools/` that runs
against a local instance on PostgreSQL and measures response times (median and 95th percentile)
and database connections in use for: signed-in people opening the home, Outside agents and
Approvals pages; outside agents screening actions and reporting runs with their keys; the Teams
webhook answering card actions. Number of people and agents are parameters. Write the results
for 50, 200 and 1,000 people and 25 and 100 agents in `docs/deploy-azure.md`, with the machine it
ran on, and say what limits first (CPU, database connections, the pool size, locks).

## 7. Lock the settings that must not change in production

Branch `codex/locked-settings`. In the Azure kit's settings overlay (the file
`SECOND_SHIFT_CONFIG_OVERLAY` points at) and with the deployment-lock mechanism the Settings page
already honours (`[settings] locked = [...]` or the environment variables; read
`maverick/editable_settings.py` and `docs/defaults.md`), lock these, which Claude recommended and
Chris may change:

- a second person must approve every waiting request (`[approval] separate_approver = "always"`);
- when the Copilot Studio gate cannot decide, it refuses (its `on_error` setting: refuse, not allow);
- Copilot Studio agents that are not enrolled are refused;
- older request signatures are refused for the whole deployment
  (`[external_agents] allow_legacy_signatures = false`).

Tests: each locked setting cannot be changed from the Settings page or its API and the page says
it is set by the deployment. Document the list in `docs/deploy-azure.md`.

## 8. First real deployment (when Chris has an Azure test subscription)

Do not start until Chris says the subscription and tenant exist. Then follow
`docs/deploy-azure.md` step by step with Chris, run `deploy/azure/check-deployment.sh`, and fix
the guide wherever reality differs. Keep a short log in `handoff/first-deployment.md` of what
failed and what was changed.

---

## Working without Claude

**Merging.** After job 1 lands, every pull request runs CI. Merge your own pull request into
`claude/friendly-shannon-e8jwva` only when CI is green, both suites passed locally, and you have
re-read your own diff against the rules below. Until CI exists, merge job 1 after the full local
runs pass.

**Claude's review queue.** If a pull request changes any of these, still merge it when green, but
add one line (pull request link, files, one sentence on what changed) to
`handoff/claude-review-queue.md` so Claude can review them in one batch later:
`maverick_dashboard/auth.py`, `maverick_dashboard/external_gateway.py`,
`maverick/external_identity.py`, `maverick/agent_trust.py`, `maverick/external_agents.py`,
`maverick/record_documents.py`, `maverick_dashboard/oidc_login.py`,
`maverick_dashboard/sign_in_roles.py`, `maverick_dashboard/rbac.py`,
`maverick_dashboard/teams_bot.py`, `maverick/copilot_studio_gate.py`, any `deploy/azure/*.bicep`
that changes network access, identities or Key Vault access, and anything about secrets.

**Rules Claude has been enforcing in review** (in addition to `AGENTS.md`):

1. A record the app keeps goes through `maverick.record_documents` (`at(path).read_text()`,
   `write_text`, `exists`, `locked`), never straight to a file, so it lands in Postgres when the
   database is Postgres. Tests for it use the `records_in_postgres` fixture in
   `tests/new/conftest.py` and assert no file appeared and the row is in `second_shift_records`.
2. A record that was encrypted with the deployment key stays encrypted in Postgres
   (`crypto_at_rest.seal_to_str` / `unseal_from_str`).
3. Fail closed: unreadable, corrupt or unreachable means refuse, never "empty, carry on" for
   anything that decides access, approval, containment or replay.
4. Never skip, loosen or delete a test to get green. If an existing test must change, say why in
   the pull request.
5. Write the failing test before the fix, and run it to see it fail.
6. Messages people read say what happened and what to do next, and the advice must fit where the
   record lives (a file or the database).
7. Every Microsoft, Azure, ServiceNow or Workday fact gets a documentation link beside it, and
   the pull request says what was not confirmed. Do not guess.
8. Commits are authored as Chris (`Christopher Day
   <131784708+cdayAI@users.noreply.github.com>`), with no AI attribution or co-author lines.
9. Local Postgres for the second suite: a PostgreSQL 16 login that may create databases in
   `MAVERICK_PG_DSN`. If Postgres was stopped (connection refused everywhere), start it again;
   that is not a test failure.
