# Work for Codex on Second Shift, round 3

Each job: start from the latest `claude/friendly-shannon-e8jwva`, read `AGENTS.md`, work on its
own branch, open a pull request against `claude/friendly-shannon-e8jwva`. Before opening it,
run the whole suite in both postures and lint, as `AGENTS.md` says, and say in the pull request
which commands you ran and their final lines. Confirm every Microsoft or Azure fact (resource
types and API versions, Graph permission names, CLI flags) from Microsoft's own documentation and
cite the URL next to it; say plainly what you could not confirm. Nothing here has a live Azure
subscription or tenant to test against: write it so it can be checked without one, and list what
still needs a real tenant. Do not add attribution or co-author lines to commits or pull requests.
Delete this file in the last pull request you open.

The app runs as one copy for everyone (one Container App replica, one process). Do not design for
several copies.

---

## 1. Continuous integration (do this first)

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

## 2. Register Second Shift in Entra ID with one script

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

## 3. The Teams bot in the Azure kit

Branch `codex/teams-bot-azure`. Add the Azure Bot resource to the Bicep kit: single-tenant,
messaging endpoint `<public origin>/webhook/teams` (`maverick_dashboard/teams_bot.py`), the
Microsoft Teams channel enabled, using the app identity `docs/teams-approvals.md` describes.
Behind a parameter so a deployment without Teams creates nothing. Update
`docs/teams-approvals.md` and `docs/deploy-azure.md` with how to build the Teams app package
(`teams-app/build_package.py` already exists) and upload it in the Teams admin center.

## 4. Watch the deployment itself

Branch `codex/azure-monitoring`. Add to the Bicep kit an action group (an operator email
address as a parameter) and alert rules for: the app restarting or not ready, a rise in 5xx
responses, the PostgreSQL server's CPU, storage and failed connections, the Azure Files share
nearing its quota, and log queries on the app's own warnings that people would otherwise miss
(alerts that cannot reach anyone, "saved record unavailable", the audit record being
unavailable). Plain-language alert names and descriptions. Document each alert and what to do
when it fires in `docs/deploy-azure.md`.

## 5. A check to run right after each deployment

Branch `codex/post-deploy-check`. `deploy/azure/check-deployment.sh <public origin>`: the
health endpoints answer; sign-in redirects to the tenant's Entra login; the public agent schema
is served; a request to the agent gateway without a key is refused before its body is read; an
unsigned request to the Teams webhook is refused. With an administrator credential from Key
Vault (optional), it also enrolls a throwaway agent, has it screen one harmless action with its
key, checks a wrong key is refused, and removes the agent again. Prints a pass/fail line per
check in plain words and exits non-zero on any failure. Never prints a key or token.

## 6. How many people one copy can serve

Branch `codex/load-check`. A developer tool (not a server dependency) under `tools/` that runs
against a local instance on PostgreSQL and measures response times (median and 95th percentile)
and database connections in use for: signed-in people opening the home, Outside agents and
Approvals pages; outside agents screening actions and reporting runs with their keys; the Teams
webhook answering card actions. Number of people and agents are parameters. Write the results
for 50, 200 and 1,000 people and 25 and 100 agents in `docs/deploy-azure.md`, with the machine it
ran on, and say what limits first (CPU, database connections, the pool size, locks).
