# Second Shift

Governance for AI agents that run on other platforms, an agent factory, and
work discovery (Ekko).

## Status

Early. What is here so far is the core library and its tests:

- **Outside-agent governance** (`maverick/external_agents.py`,
  `agent_control_plane.py`, `agent_trust.py`, `agent_edr.py`, `revocation.py`,
  `killswitch.py`): enroll an agent, issue its credential, screen an action
  before it happens, record runs, cap spend, contain, suspend and release.
- **Ekko work discovery** (`maverick/ekko_*.py`, `work_discovery*.py`): the
  content-free desktop recorder, its local store, and repeated-work discovery.
- The storage, settings, audit-log and encryption modules those depend on.

The web application, the agent factory and the AI asset inventory are not in
this repository yet.

## Develop

Python 3.11 or 3.12.

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/pip install -e '.[postgres,dev]'
```

```bash
.venv/bin/python -m pytest -q -n auto --dist loadfile
```

Settings are read from `~/.maverick/config.toml`; environment variables use the
`MAVERICK_` prefix (`SECOND_SHIFT_` is accepted as an alias).
