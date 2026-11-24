# Platform checks

Second Shift governs agents that run on other platforms. Without platform
checks it knows only what an enrolled agent tells it. A platform check asks the
agent's home platform directly which agents exist there and how each one is
set up, so that:

- a change to an agent's set-up is noticed even if the agent never reports it;
- agents that exist on the platform but were never enrolled are listed.

Platform checks only read. They never change, switch off or delete anything on
a platform, and they take no action on what they find: a changed set-up shows
up as a drift finding ("the agent's configuration on its home platform no
longer matches the approved one"), and what happens next follows your drift
settings.

Platform checks are off until you turn them on. Nothing in this note has been
run against a live Microsoft tenant; see "Limits" for what that means.

## What one check does

1. For each platform you listed, it signs in and asks for the full list of
   agents.
2. An agent on that list that matches an enrolled agent has its set-up
   fingerprint handed to drift detection. If the fingerprint differs from the
   one in the agent's approved baseline, that is a high-severity drift finding.
3. Agents on the list that no enrolled agent claims are kept as "found on the
   platform, not enrolled".
4. An enrolled agent that its platform did not list is counted as absent. After
   it has been absent for several checks in a row (three unless you change it)
   it is marked "missing on the platform". It is cleared the next time the
   platform lists it.

A platform either gives its complete list or the check of that platform fails.
A list that is too long, an answer that is not in the expected form, or a list
that loops back on itself is reported as an error; it is never treated as a
shorter list. When one platform fails, the others are still checked, and what
was already known about the failed platform is kept as it was.

Each check writes one line to the audit log (`agent_watch_synced`) holding
counts only.

## Turning it on

Outside-agent governance must be on. Then add to the settings file
(`~/.maverick/config.toml`):

```toml
[agent_watch]
enable = true
platforms = ["entra_agent_id", "foundry", "copilot_studio"]

[agent_watch.entra_agent_id]
tenant_id_env = "SS_MS_TENANT_ID"
client_id_env = "SS_MS_CLIENT_ID"
client_secret_env = "SS_MS_CLIENT_SECRET"

[agent_watch.foundry]
tenant_id_env = "SS_MS_TENANT_ID"
client_id_env = "SS_MS_CLIENT_ID"
client_secret_env = "SS_MS_CLIENT_SECRET"
endpoints = ["https://contoso-ai.services.ai.azure.com/api/projects/sales"]

[agent_watch.copilot_studio]
tenant_id_env = "SS_MS_TENANT_ID"
client_id_env = "SS_MS_CLIENT_ID"
client_secret_env = "SS_MS_CLIENT_SECRET"
environments = ["https://contoso.crm4.dynamics.com"]
```

List only the platforms you use. The variable names above are examples; use
any names you like.

| Setting in `[agent_watch]` | Meaning | Default | Allowed |
| --- | --- | --- | --- |
| `enable` | Turns platform checks on. `MAVERICK_AGENT_WATCH=1` or `0` in the environment overrides it. | `false` | `true` / `false` |
| `platforms` | The platforms to check, by name. | none | up to 20 names |
| `sync_minutes` | How often the scheduled check runs. | 60 | 5 to 1440 |
| `missing_after_runs` | Successful checks in a row an enrolled agent may be absent before it is marked missing. | 3 | 1 to 30 |
| `max_agents` | The most agents one platform may list in one check. More than this is an error. | 2000 | 1 to 20000 |
| `max_pages` | The most requests one platform's check may make. More than this is an error. | 100 | 1 to 1000 |
| `timeout_seconds` | How long to wait for one answer. A whole platform check may take 15 times this. | 20 | 2 to 120 |

A number outside its range is brought to the nearest allowed value. A value of
the wrong kind is ignored and the default is used. If a platform's own section
is wrong, that platform is not checked and the status page says why; the other
platforms carry on. Messages never repeat the value you typed, in case it was a
secret.

### Credentials

Each Microsoft check signs in as an app registration with a client secret.
The settings hold the NAMES of three environment variables, never the values:
the directory (tenant) id, the application (client) id and the client secret.
The values are read at the moment of each check, so a replaced secret is picked
up without a restart. If your installation reads secrets from mounted files,
the same names are looked up there first.

A section that contains `client_secret = "..."` is refused. The access token
Microsoft returns is kept in memory until two minutes before it expires and is
never written to disk, to the log or to the saved record.

You can use one app registration for all three checks, or one per check.

## Linking an enrolled agent to its platform agent

A check matches a platform agent to an enrolled agent through the enrolled
agent's external reference, written as `<platform>:<id on that platform>`:

| Platform | External reference | Example |
| --- | --- | --- |
| `entra_agent_id` | the agent identity's object id | `entra_agent_id:1b7313c4-05d0-4a08-88e3-7b76c003a0a2` |
| `foundry` | resource, project and agent name | `foundry:contoso-ai/sales/quote-agent` |
| `copilot_studio` | environment host and agent (bot) id | `copilot_studio:contoso.crm4.dynamics.com/49b0be2e-d01c-ed11-b83e-000d3a572421` |

Capital and small letters are treated as the same. The "not enrolled" list
shows the exact reference to use for each agent it found.

## The Microsoft checks

None of these uses the Microsoft Agent 365 registry, so no Agent 365 licence is
needed.

### Entra Agent ID (`entra_agent_id`)

**Reads:** the agent identities in your Microsoft Entra tenant, with one call
to Microsoft Graph: `GET https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity`,
followed page by page.

**Permission to grant:** on the app registration, the Microsoft Graph
*application* permission `AgentIdentity.Read.All`, with admin consent.

**What counts as a change:** the identity's display name, whether its account
is enabled, which blueprint it was made from, whether Microsoft has disabled
it, and its service principal type. Tags are left out on purpose, because they
also change whenever the blueprint's tags change.

**Cannot see:** what the identity is allowed to do (role assignments and
permission grants), who owns or sponsors it, or when it was last changed. Entra
gives an agent identity no version number and no "last modified" time, so those
are shown blank.

### Microsoft Foundry (`foundry`)

**Reads:** the agents of each project you list, each with its latest version,
with one call per project to the Foundry Agent Service:
`GET <project endpoint>/agents?api-version=v1&limit=50&order=asc`, followed page
by page.

**Settings:** `endpoints`, a list of 1 to 20 project endpoints of the form
`https://<resource>.services.ai.azure.com/api/projects/<project>`.

**Permission to grant:** give the app registration an Azure role on the Foundry
resource (or the project) that lets it read agents. Microsoft's built-in role
for this is **Foundry User** (previously called Azure AI User, role id
`53ca6127-db72-4b80-b1b0-d745d6d5456d`). That role can also make changes; the
check never does. If you want a role that can only read, create a custom role;
we could not confirm from Microsoft's pages the exact name of the "read agents"
action, so check it against Microsoft's role documentation. Microsoft also
requires the Foundry resource to have a custom subdomain for this kind of
sign-in.

**What counts as a change:** a new version of the agent, or any change to the
latest version's kind, model, instructions or tools. Instructions and tool
settings are turned into fingerprints as they are read and are never kept.
Foundry versions cannot be edited once made, so this is the strongest of the
three checks.

**Cannot see:** draft versions (Foundry leaves them out of "latest"), what an
agent said or did, or agents in projects you did not list. For agents that are
not prompt agents (hosted or workflow agents, for example) only the version and
kind are fingerprinted; a new version still shows as a change. Switching an
agent on or off shows in its state but is not treated as a set-up change.

### Copilot Studio (`copilot_studio`)

**Reads:** the Agent (`bot`) table of each Power Platform environment you list,
with one call per environment to the Dataverse Web API:
`GET <environment>/api/data/v9.2/bots?$select=botid,name,schemaname,publishedon,modifiedon,statecode,statuscode&$orderby=botid`,
followed page by page.

**Settings:** `environments`, a list of 1 to 20 environment addresses of the
form `https://<name>.crm.dynamics.com` (the middle part is `crm4`, `crm11` and
so on outside North America). Use the environment address itself, not the
"Web API endpoint" with `.api.` in it and not an address with a path.

**Permission to grant:** in each environment, add the app registration as an
*application user* (Power Platform admin center > the environment > Settings >
Users + permissions > Application users) and give it a security role that can
read the Agent table for the whole organization. A custom role with only that
is enough. An application user needs no licence, and the app registration needs
no Dynamics API permission for this.

**What counts as a change:** the time the agent was last published, the time
its record was last modified, and its status.

**Cannot see:** topics, knowledge sources, actions and connections. They live
in other tables that are not read, so an edit to them shows only when the agent
is next published. The large configuration column is not read either; a change
to it moves the "last modified" time. Agents in environments you did not list
are not seen: Microsoft's tenant-wide inventory needs a signed-in person, not
an app. Agents built for Microsoft 365 Copilot without Copilot Studio are not
covered.

## Limits

- **Not run against a live tenant.** The checks follow Microsoft's published
  pages (listed below). Only what a check cannot work without is required: an
  agent's identifier, for Foundry its latest version, and for Copilot Studio
  its "last modified" time. Every other field is optional, so a missing field
  does not break a check. A field that arrives in an unexpected shape fails
  that platform's check with a plain message instead of being guessed at. If
  Foundry ever lists an agent with no released version at all, that project's
  check fails until we have seen how Microsoft reports such an agent.
- **A check sees what its app registration may list**, on the platforms,
  projects and environments you named, and nothing else.
- **Changes are noticed at the next check**, not at once. The scheduled check
  runs every `sync_minutes`; an administrator can also start one by hand, and a
  check started by hand counts towards "missing" like any other.
- **One project or environment failing fails that platform's whole check.**
  This is deliberate: a partial list would make the agents in the failed
  project look as if they had disappeared.
- **Copilot Studio's "last modified" time** may move for reasons that are not a
  real change to the agent. We could not confirm how often Microsoft does
  this. If it produces findings that turn out to be nothing, acknowledge them
  and tell us.
- **One external reference per enrolled agent.** An agent that appears on two
  platforms (for example a Foundry agent and its Entra agent identity) is
  matched on the one you named and stays on the "not enrolled" list of the
  other.
- **Microsoft public cloud only.** The sign-in, Graph, Foundry and Dataverse
  addresses are fixed. Government and other national clouds are refused in the
  settings.
- **Direct connections only.** The checks connect straight to Microsoft and do
  not use an outbound proxy. If your installation restricts outbound
  connections, allow `login.microsoftonline.com`, `graph.microsoft.com`, your
  `<resource>.services.ai.azure.com` and your `<name>.crm*.dynamics.com`
  hosts. A resource reachable only through a private endpoint is refused
  unless you have allowed private addresses for fetches.
- **Client secrets only.** Certificates and managed identities are not
  supported for sign-in.
- **The "not enrolled" list keeps at most 500 agents per platform.** The status
  shows the full count next to the number shown.

## What is kept

One file, `external_agents_watch.json`, beside the enrollment record, readable
only by the service account. It holds, per platform, the times of the last
attempt and last success, the last error in plain words, and counts; the
"not enrolled" list with the first and last time each agent was seen; and, per
enrolled agent, what its platform last said (state, version, last change, last
seen, how many checks it has been absent). It never holds a secret, a token,
or anything copied from a platform's answer beyond names, states and version
labels.

If this file cannot be read, checks stop and say so, before any platform is
contacted. The file is never overwritten or treated as empty. Restore it from
a backup, or move it aside to start again.

## When a check fails

The status shows the last error for each platform in plain words. The common
ones:

| Message says | What to do |
| --- | --- |
| the environment variable named by a setting is not set | Set the variable, or correct its name in the settings. |
| the sign-in service refused the sign-in | Check the tenant id, client id and secret, and that the secret has not expired. |
| the platform refused this check (HTTP 403) | Grant the permission described above for that platform. |
| nothing at the address (HTTP 404) | Check the project endpoint or environment address. |
| the platform listed more than N agents / did not end within N pages | Raise `max_agents` or `max_pages` if the number is expected. |
| the answer was not in the expected form | Microsoft's answer did not match its documentation. Nothing from that check was used; report it. |
| network rules do not allow connections | Allow the hosts listed under "Limits". |

## For integrators

- `GET /api/v1/agent-watch` (view permission): the status of each platform and
  the "not enrolled" list.
- `POST /api/v1/agent-watch/sync` (admin permission): run a check now and
  return its summary. It takes no input; the addresses a check uses come only
  from the settings above.

Both answer 404 while outside-agent governance is off.

## Microsoft pages these checks follow

- Sign-in (OAuth 2.0 client credentials): https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
- List agent identities, and its permission: https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0
- The agent identity resource: https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0
- Paging in Microsoft Graph: https://learn.microsoft.com/en-us/graph/paging
- Foundry Agent Service overview: https://learn.microsoft.com/en-us/azure/foundry/agents/overview
- Foundry project endpoint and `api-version=v1`: https://learn.microsoft.com/en-us/azure/foundry/agents/quickstarts/prompt-agent
- Foundry sign-in scope and roles: https://learn.microsoft.com/en-us/azure/foundry/concepts/authentication-authorization-foundry
- Foundry REST reference: https://learn.microsoft.com/en-us/azure/foundry/reference/foundry-project, which leads to
  https://ai.azure.com/api-reference ("List agents": https://ai.azure.com/api-reference/llm/agents/list-agents.md)
- The Dataverse Agent (`bot`) table: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/bot
- Dataverse Web API requests and headers: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/compose-http-requests-handle-errors
- Dataverse Web API paging: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/query/page-results
- Dataverse sign-in as an app: https://learn.microsoft.com/en-us/power-apps/developer/data-platform/authenticate-oauth
- Application users in an environment: https://learn.microsoft.com/en-us/power-platform/admin/manage-application-users
- Why the tenant-wide Copilot Studio inventory is not used (it needs a signed-in person): https://learn.microsoft.com/en-us/power-platform/admin/inventory-api
