# Second Shift

Governance for AI agents that run on other platforms, an agent factory, and
work discovery (Ekko).

## Status

Early. What works today:

- **Outside-agent governance.** Enroll an agent that runs on another platform,
  issue its credential, screen an action before it happens, record its runs
  and spend, cap its budget, contain it after repeated refusals, and suspend
  or release it. Operators use the **Outside agents** and **Agent controls**
  pages; agents call the API under `/api/v1/external/`.
- **Sign-in.** OpenID Connect (for example Microsoft Entra ID), or a single
  break-glass token. With neither configured the app only answers on the
  local machine.
- **Ekko work discovery, core only.** The content-free desktop recorder, its
  local store and repeated-work discovery. Its pages are not here yet.

Not here yet: the approvals queue page, the agent factory, the AI asset
inventory, drift views, and the Ekko pages.

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
