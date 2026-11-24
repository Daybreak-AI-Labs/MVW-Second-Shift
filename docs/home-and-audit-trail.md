# Home and the audit trail

Two pages answer two questions: what needs me today, and what happened.

## Home

Home (`/`) is the first page after sign-in. It lists what is waiting on the
person looking at it, as far as their permissions reach, most serious first and
newest first. Each line opens the place where it is dealt with.

| Section | Who sees it | What it lists |
| --- | --- | --- |
| Waiting for your decision | people who can decide approvals | requests waiting for a decision, linking to the request on the Approvals page |
| Agents behaving differently | everyone who can view | drift findings nobody has acknowledged, linking to the agent |
| Agents that are blocked, over budget or paused | everyone who can view | agents blocked for rule breaks, over their budget, or paused |
| Found on your platforms | everyone who can view | platform checks that failed or need settings attention, agents added here that left their platform, and agents found on a platform that nobody added |
| Access keys that are ending | administrators | agents whose access ended or ends within 14 days |
| Alerts | administrators | alerts that are switched off, have nowhere to go, or are not ready |

When nothing needs attention Home says so and lists what it is watching.

Home only reads. It never runs a drift check or a platform check and never
sends an alert; those keep their own schedule and buttons. Nothing is cached
between requests. If one source cannot be read, its section shows one line
saying so, the rest still show, and Home does not say "all clear".

## Audit trail

The audit trail (`/audit`) is open to people who hold the audit permission
(administrators, governance leads and auditors). It reads the signed audit log
and changes nothing, except that an export is itself recorded.

- **Entries** are listed newest first in plain words: who, what, which agent
  and when. "Raw fields" shows the entry exactly as the log holds it. The log
  holds no content of anyone's work by design, and the page adds none.
- **Filters**: dates, kind of event (approvals, outside agents, drift, platform
  checks, sign-in and roles, settings, emergency stop, Ekko, the audit trail
  itself, other), agent and person. Pages hold 50 entries. To keep the page
  quick it searches the newest 10,000 entries of each day and at most 20,000
  entries in all; when a limit cut a read short the page says so. Narrow the
  dates to reach older entries.
- **Integrity check**: the button checks the signature chain of the newest 30
  days (up to 90 with `?days=`) and says whether anything was changed or
  removed after it was written. It runs only when asked. A trail with unsigned
  days, or days that could not be read, is never reported as passing.
- **Export** downloads the filtered entries as CSV or JSON, up to 10,000. The
  export is written to the audit log (who, format, how many, which dates and
  kind of event, and whether an agent or person filter was used, but not what
  was typed into those filters) before any data is sent. If the audit log
  cannot record it, nothing is exported. CSV cells that start with `=`, `+`,
  `-` or `@` are prefixed with `'` so a spreadsheet does not run them.

An auditor has this page and the read-only pages (Home, Outside agents and
Agent controls) and can change nothing.
