# Connect an agent

Second Shift governs agents that run on other platforms. This note covers the
guided path on the Outside agents page, what each platform needs, and the
starter rules offered when you add an agent. The page writes the same steps in
plain words next to each agent.

## The three levels

Every agent on the Outside agents page is at one of three levels:

- **Watched**: a platform check found it on its platform and nobody added it
  to Second Shift. It works outside your rules. Press **Add this agent**; the
  add form opens with its name, platform and platform record filled in.
- **Added**: added here, but Second Shift has not heard from it yet (no
  screening call and no run report).
- **Connected**: it has called Second Shift at least once. The roster shows when
  it was last heard from and whether that was a screening call or a run report.

The time is written at most once a minute per agent, so it can be up to a
minute behind the agent's latest call. Use the filters above the list to show
one level or one platform; the counts at the top always cover everyone.

## The guided path

After you add an agent (or press **Connect it** on its row) the page opens
three steps without leaving the page:

1. **Create the access key.** It is shown once. Paste it where your platform
   keeps secrets, never into the agent's instructions. Creating another key
   replaces the first at once.
2. **Put the connection in your platform** (below).
3. **Waiting to hear from the agent.** The page asks every few seconds whether
   the agent has called. Run the agent once. When it calls, the page turns to
   **Connected** with the time and what was received. After about four minutes
   it stops and says so; press **Check again** to start over.

The question the page asks needs the view permission and returns only the
agent's level, when it was last heard from and what that call was.

## What to do on each platform

None of the steps below has been tested in a real tenant. They follow each
platform's documentation and Second Shift's own connection file. If a step does
not match what you see, the platform's screen has probably changed; the
connection file and the access key are the same in every case.

### Microsoft Foundry and custom agents

The agent calls the connection API over HTTPS with the access key as a bearer
key.

1. Download the connection file from the Outside agents page (an OpenAPI
   description, `second-shift-connection.json`).
2. Foundry: add it to the agent as an OpenAPI tool, with the key stored as a
   connection secret. Custom agents: call the two addresses from your own code.
3. Make the agent ask first. Before an action that changes something it calls
   the screening address and waits for an answer; when a task ends it reports
   the run.

The Python runtime and client kits are coming. Until then the connection file
and these notes are the way in. Not tested in a real Foundry project.

### Microsoft Copilot Studio

If an administrator has turned on the Copilot Studio gate for the agent's
environment (`[copilot_studio_gate] environments` in the settings file, which
names the environments the gate covers), there is nothing to do for each
agent: the page says so and no access key is needed. A missing, empty or
unreadable setting counts as "no gate". If the agent has no platform record
the page cannot tell which environment it is in; it says so and shows the
per-agent steps as well.

Without the gate, per agent: create the access key, then in Copilot Studio add
a tool from an OpenAPI file with the connection file and bearer-key sign-in,
and tell the agent in its instructions to use the screening tool before any
action that changes something. Not tested in a real Copilot Studio
environment, and the gate itself is described in its own notes.

### ServiceNow, Workday and other platforms

These use the connection API as above: call the screening address before each
risky action and the run address when a task ends, from a Flow Designer action
or REST message (ServiceNow), an integration or extend app (Workday), or the
platform's own way to call an HTTPS API. Keep the key in the platform's secret
store. Not tested in a real ServiceNow instance or Workday tenant.

## Starter rules

When you add an agent you can start from one of three sets of rules. They fill
the limits on the form and you can change any of them before saving; the
agent's record keeps which starter you began from. They are starting points
chosen by the developers of Second Shift, not policy: an administrator should
review them against your own rules.

| Starter | Riskiest action | A person approves | Monthly spending limit | Access keys last |
| --- | --- | --- | --- | --- |
| Customer-facing | Low | Medium or higher | $25 | 30 days |
| Internal helper | Medium | High | $100 | 90 days |
| Finance or HR data | Medium | Medium or higher | $25 | 30 days |

"A person approves" is a setting on the agent. Your organisation-wide setting
(`[actions] require_approval_at`) still applies and the stricter of the two
wins, so an agent's own setting can only ask for more approvals, never fewer.
