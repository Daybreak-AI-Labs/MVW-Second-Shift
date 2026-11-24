# Defaults an administrator should know

Second Shift starts safe. This page lists each default that changes what
people see or what an agent may do, what it does, and how to change it.
Settings live in `config.toml` (see [Alerts](alerts.md) for where it is).

| Default | Value | What it does |
| --- | --- | --- |
| Second person approves | `always` | A person who asked for a high-risk or critical request can never approve it themselves. |
| Approval needed from | `high` | A person must approve each action rated high risk or above. |
| Reminder before a request runs out | 25% of its time left | One reminder, then one note if it runs out undecided. |
| Access key warning | 14 days before | One warning, then one note when the key has ended. |
| Alerts | off | Nothing is sent until an administrator turns alerts on. |
| Drift learning period | 14 days | Changes after a baseline is approved are recorded but not alerted. |
| Starter rule sets | three | Starting limits offered when an agent is added. |

## A second person approves high-risk requests

```toml
[approval]
separate_approver = "always"   # or "when_available", or "never"
```

With roles coming from Microsoft Entra, Second Shift cannot always see who else
could approve a request. So by default the person who asked for a high-risk or
critical request cannot approve it, even if nobody else can. The request then
waits and, if nobody else decides it, runs out and the action is refused.
Rejecting your own request is always allowed.

- `always` (default): never the requester.
- `when_available`: not the requester when someone else could decide it; a
  one-person installation may approve its own request, and Second Shift records
  that it did.
- `never`: the requester may approve.

`MAVERICK_SEPARATE_APPROVER` overrides the file. A value Second Shift does not
know is treated as `always`. A bypass of failing agent tests always needs
someone else, whatever this says.

## Reminders before a waiting request runs out

A request from an outside agent waits 24 hours for a decision. If nobody
decides it, it runs out and the action is refused.

```toml
[approval]
reminder_fraction_left = 0.25   # remind when this share of the time is left; 0 = never
```

When a request is still waiting with that share of its time left, Second Shift
sends one alert, and one fresh card in Teams when Teams approvals are on. If it
runs out undecided it sends one note. Each goes out at most once per request;
what was sent is saved, so a restart sends nothing again. Nothing is sent while
alerts and Teams are both off. Requests of other kinds have no time limit and
get no reminder.

## Access keys

```toml
[agent_keys]
expiry_warning_days = 14   # 0 = never warn
```

Administrators are alerted once when an agent's access key will end within this
many days, and once when it has ended. The home page lists the same keys. A
renewed key (a new end date) is warned about again. The starter rule sets give
keys 30 or 90 days.

## Alerts

```toml
[alerts]
enabled = false            # the default
backends = ["teams", "email"]
```

Alerts are off until you turn them on, so a fresh install tells nobody about a
blocked agent, a drift finding or a request about to run out. Second Shift says
so in three places: a warning in the log at start-up when outside-agent
governance is on and alerts are off or have no working channel, a line on the
home page, and the alert delivery strip on the Outside agents page. See
[Alerts](alerts.md) to set up Teams or email and send a test.

## A quieter first few weeks for drift

```toml
[agent_drift]
learning_days = 14   # 0 = no learning period
```

For this many days after a baseline is approved, a change is recorded and shown
on the agent's page marked "Learning period", but it is not alerted and never
contains the agent automatically (`on_drift = "contain"` waits). The agent's
page shows when the period ends. If the change is still there afterwards, it is
reported then. The exception: a high-severity change to the agent's set-up on
its home platform always alerts at once.

## Starter rule sets

When an agent is added, the form offers a starting point (change anything
before saving; review them against your own rules):

| Set | Riskiest action | Person approves from | Spending limit | Key lasts |
| --- | --- | --- | --- | --- |
| Customer-facing | low | medium | $25 a month | 30 days |
| Internal helper | medium | high | $100 a month | 90 days |
| Finance or HR data | medium | medium | $25 a month | 30 days |

The sets are in `maverick/starter_rules.py`. An organisation-wide
`[actions] require_approval_at` can only make an agent's approval level
stricter, never looser.
