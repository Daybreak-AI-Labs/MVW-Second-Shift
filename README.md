# Second Shift

Governance for AI agents that run on other platforms, an agent factory, and
work discovery (Ekko).

## Status

Early. What works today:

- **Outside-agent governance.** Enroll an agent that runs on another platform,
  issue its access key, screen an action before it happens, record its runs
  and spend, cap its budget, contain it after repeated refusals, and suspend
  or release it. Operators use the **Outside agents** and **Agent controls**
  pages; agents call the API under `/api/v1/external/`, described by the
  connection file at `/api/v1/external/openapi.json`.
- **Approvals.** A risky action an agent asks about waits on the **Approvals**
  page until a person approves or rejects it. A high-risk approval needs an
  acknowledgement, and the decision is bound to the exact request the person
  saw. The person is shown the agent's own description of the action
  (shortened, secrets removed); set `[external_agents] show_request_detail =
  false` to keep requests content-free.
- **Drift.** Each enrolled agent's activity is recorded as daily totals. An
  administrator approves a baseline; after that a new tool, a shifted tool
  mix, changed volume or cost, more refusals or failures, a changed model,
  version or configuration, or an agent that stops reporting is shown on the
  agent's page, written to the audit log and alerted once. Set
  `[agent_drift] on_drift = "contain"` to also block an agent on a
  high-severity change. A run report may carry the names of the tools used
  (`tools`) and the agent's own version, configuration digest and model
  (`declared`).
- **Platform checks.** Second Shift can ask Microsoft Entra Agent ID,
  Microsoft Foundry and Copilot Studio which agents exist and how each is set
  up, so a change is noticed even when the agent reports nothing and agents
  nobody enrolled are listed. See [docs/platform-checks.md](docs/platform-checks.md).
- **Alerts.** To a Microsoft Teams channel and by email, with a test call for
  administrators. See [docs/alerts.md](docs/alerts.md).
- **Sign-in and roles.** OpenID Connect (for example Microsoft Entra ID), or a
  single break-glass token. With neither configured the app only answers on
  the local machine. A person's role can come from the app roles in their
  sign-in token. See [docs/sign-in-roles.md](docs/sign-in-roles.md).
- **Ekko work discovery, core only.** The content-free desktop recorder, its
  local store and repeated-work discovery. Its pages are not here yet.

Not here yet: the agent factory, the AI asset inventory, the Ekko pages, and
platform checks for ServiceNow and Workday.

Not yet proven outside this repository's tests: nothing has been run against a
live Microsoft tenant, a real Teams channel, a real mail server or a Postgres
server.

## Run

Python 3.11 or 3.12.

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/pip install -e '.[postgres,dev]'
```

```bash
MAVERICK_EXTERNAL_AGENTS=1 MAVERICK_CONTROL_PLANE=1 .venv/bin/python -m maverick_dashboard.app
```

Then open http://127.0.0.1:8765/. Run one instance per data folder: records
are hash-chained and assume a single writer, and a second instance refuses to
start.

## Test

```bash
.venv/bin/python -m pytest -q -n auto --dist loadfile
```

## Settings

Settings are read from `~/.maverick/config.toml`; environment variables use the
`MAVERICK_` prefix (`SECOND_SHIFT_` is accepted as an alias). Sign-in with an
identity provider is configured in the `[auth.oidc]` section.
