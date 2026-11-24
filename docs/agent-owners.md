# Agent owners

Every outside agent has an owner: the person who answers for it. Owners are
usually not administrators, so Second Shift gives them a page of their own
agents and a short note each week with what needs them. This page says what
owners see, how Second Shift decides who owns an agent, and the weekly note and
its settings.

## What an owner sees

Anyone who is signed in and can view Second Shift can open **My agents**
(`/my-agents`, under AI oversight). For each agent they own it shows:

- its level: **Watched**, **Added** or **Connected**, and when Second Shift last
  heard from it;
- whether it is active, paused or blocked;
- whether it still matches the baseline an administrator approved, and how many
  changes nobody has acknowledged yet;
- what its platform check last said: found, changed, no longer found, or not
  checked;
- changes in the models it uses that nobody has acknowledged;
- what it has spent against its limit, this month or in total;
- how many requests about it are waiting for a decision;
- when its access key ends;
- a link to the agent's own page.

The page only reads. It never runs a drift check or a platform check; it shows
what the last check found. A part that cannot be read says so instead of
looking fine.

A person who also holds the permission for an action finds it where it always
was: **Approvals** for deciding requests (approve), **Agent controls** for
pausing and resuming (respond), and the agent's own page for everything an
administrator can do (admin). Everyone else sees the page read-only, and it
says that an administrator can change the agent. Someone who owns no agents
sees a short explanation of how an agent comes to be theirs.

## How ownership is matched

The owner of an agent is set when it is added: an email address and, when the
Entra directory is on and the owner was chosen from the people picker, the
owner's Entra object id. Second Shift matches the person who is signed in to
those fields, and only on what their sign-in proves:

- **Email.** The person's email counts only when the identity provider marked
  it verified. It is compared without regard to letter case with an owner that
  is an email address. An email the provider did not verify, a user principal
  name, a display name and the opaque sign-in subject never match.
- **Object id.** When the sign-in carries the Entra object id (the `oid` claim
  of a verified ID token), it counts too. When both the owner record and the
  sign-in have an object id, the object id decides: an email address can later
  be given to someone else, an object id cannot. A browser sign-in does not
  keep the object id, so there the email decides.
- **Trusted proxy.** With sign-in through a trusted reverse proxy, the
  identity the proxy forwards counts as an email when it is one.
- **Never a name.** An owner written as a name ("Jo Smith") matches nobody by
  that name. Edit the agent and pick the person, or enter their email address.

Signed in with a shared access token, or with sign-in switched off, nobody is
identified as a person and the page says Second Shift cannot tell who they are.

## The weekly note

Each owner gets at most one email a week listing only what needs them:

- agents that changed on their platform, or are no longer found there;
- changes in behaviour or set-up that nobody has acknowledged;
- changes in the models they use that nobody has acknowledged;
- agents that are blocked or paused;
- spending above 80% of the limit;
- access keys that end within the warning window (`[agent_keys]
  expiry_warning_days`, 14 days by default) or have ended;
- requests about their agents that are still waiting;
- agents nobody has heard from, once they have been added for a day.

When nothing needs an owner, nothing is sent. The note names agents and gives
counts and links to the pages. It never contains what an agent was asked or
answered, the details of a request or a finding, or a key or any other secret.
It is plain text with a simple HTML version.

The note goes only to an owner whose agent record holds exactly one email
address. It is sent through the same email path as alerts, with the same
mail settings (see [alerts](alerts.md)); the note does nothing until alerts by
email are set up. Links are complete when `[dashboard] public_url` is set.

What was sent is recorded for each owner and week (under a one-way digest of
the address, not the address), so restarting the app never sends a note
twice. If the mail server refuses a note, it is tried again later the same
morning. The app checks every five minutes; a week's note still goes out up to
twelve hours after its scheduled time, so a short outage does not skip a week.
A week where nothing needed the owner at that time is not revisited.

### Settings

```toml
[owner_note]
enabled = false        # off by default
weekday = "monday"     # the day it goes out
hour = 8               # the hour, 0-23, in the time zone below
timezone = "UTC"       # an IANA name, for example "Europe/London"
teams = false          # also message the owner in Teams
```

A value that cannot be used (an unknown day, an hour outside 0-23, an unknown
time zone) falls back to Monday, 8 and UTC, and the settings page can show the
sentence that says so.

### Microsoft Teams

With Teams approvals on (see [teams-approvals](teams-approvals.md)) and
`teams = true`, the owner also gets a short message in their own Teams chat:
how many of their agents need them and where to look. Teams must know the
person already: they linked their account, or sent the bot a message. An
owner Teams does not know gets the email only. Teams is never required for the
email, and a Teams failure never stops it.
