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
run against a live Microsoft tenant, ServiceNow instance or Workday tenant; see
"Limits" for what that means.

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

For ServiceNow and Workday, add `"servicenow"` or `"workday"` to `platforms`
and a section for each:

```toml
[agent_watch.servicenow]
instances = ["https://contoso.service-now.com"]
client_id_env = "SS_SN_CLIENT_ID"
client_secret_env = "SS_SN_CLIENT_SECRET"

[agent_watch.workday]
region = "us"
tenant = "contoso"
client_id_env = "SS_WD_CLIENT_ID"
client_secret_env = "SS_WD_CLIENT_SECRET"
refresh_token_env = "SS_WD_REFRESH_TOKEN"
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

The ServiceNow and Workday checks follow the same rule with their own
credentials: the settings hold only the names of environment variables, the
values are read at the moment of each check, and a section that contains the
secret itself (`client_secret = "..."`, or for Workday `refresh_token = "..."`)
is refused. What each one signs in as is described in its own section below.

## Linking an enrolled agent to its platform agent

A check matches a platform agent to an enrolled agent through the enrolled
agent's external reference, written as `<platform>:<id on that platform>`:

| Platform | External reference | Example |
| --- | --- | --- |
| `entra_agent_id` | the agent identity's object id | `entra_agent_id:1b7313c4-05d0-4a08-88e3-7b76c003a0a2` |
| `foundry` | resource, project and agent name | `foundry:contoso-ai/sales/quote-agent` |
| `copilot_studio` | environment host and agent (bot) id | `copilot_studio:contoso.crm4.dynamics.com/49b0be2e-d01c-ed11-b83e-000d3a572421` |
| `servicenow` | instance host and the agent record's `sys_id` | `servicenow:contoso.service-now.com/0a1b2c3d4e5f60718293a4b5c6d7e8f9` |
| `workday` | tenant and agent definition id | `workday:contoso/9a1f0c2e4b6d8f00112233445566aabb` |

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

## The ServiceNow check (`servicenow`)

**Reads:** the AI agents built in AI Agent Studio on each instance you list,
from four tables, through the ServiceNow Table API:

| Table | What the check takes from it |
| --- | --- |
| `sn_aia_agent` | the agents: name, role, description, type, channel |
| `sn_aia_agent_config` | each agent's settings record, with its "active" switch |
| `sn_aia_version` | each agent's versions, with their instructions and state |
| `sn_aia_agent_tool_m2m` | which tools each agent may use |

Each table is read with
`GET https://<instance>.service-now.com/api/now/table/<table>?sysparm_query=ORDERBYsys_id&sysparm_fields=<a fixed list of columns>&sysparm_display_value=false&sysparm_exclude_reference_link=true&sysparm_limit=100&sysparm_offset=<n>`,
100 records at a time, until a page comes back empty. An instance therefore
takes at least four requests, and normally eight or more.

**Settings:**

- `instances`: a list of 1 to 20 addresses of the form
  `https://<instance>.service-now.com`. Use the instance's own address.
  ServiceNow lets a company add branded "custom URLs" (such as
  `https://support.example.com`). Each of those is only another name for the
  same instance, so the check does not accept them: the client secret is then
  never sent to anything but a ServiceNow address.
- `client_id_env` and `client_secret_env`: the names of the environment
  variables that hold the OAuth client id and client secret.
- `scope` (optional): OAuth scope names separated by spaces, if your
  integration only gives tokens for named scopes. Leave it out otherwise.

Every instance you list is signed in to with the same client id and secret.
Instances cloned from one another usually share them. If yours do not, list
one instance only.

**Permission to grant,** on each instance:

1. Turn on client-credentials sign-in for inbound requests. ServiceNow keeps it
   off by default: set the system property
   `glide.oauth.inbound.client.credential.grant_type.enabled` to `true`.
2. Create the integration: Machine Identity Console > Inbound integrations >
   New integration > OAuth - Client credential grant (this needs the role
   `oauth_admin`, `mi_admin` or `admin`). Its *OAuth application user* is the
   account the check acts as.
3. Give that OAuth application user the role **`sn_aia.viewer`** (AI Agent
   Viewer), which ServiceNow describes as read-only access to the AI agent
   tables. Do not give it `sn_aia.admin`; the check never needs to change
   anything.

**What counts as a change:**

- on the agent: its name, type, channel, record type, parent agent, and its
  role, description, condition and context-processing script;
- on its settings record: whether it is active, whether it is public, the user
  it runs as, advanced mode and agent learning;
- on its versions: a version being added, published, withdrawn or renamed, or
  the instructions or condition of any version that is not a draft changing;
- on its tools: a tool being added or removed, or a tool link being edited
  (for example how the tool may be run).

Role text, descriptions, scripts and instructions are turned into fingerprints
as they are read and are never kept. Editing a draft version is not a change,
because a draft is not what runs; publishing it is. The status shows the name
of the published version, whether the agent is active, and when its record was
last updated.

**Cannot see:** what an agent did (runs, messages and logs are not read); what
a tool itself does (an edit inside a tool is not seen, only the link between
agent and tool); agentic workflows, triggers and teams; the access roles an
agent takes on; ServiceNow's AI assets inventory; and agents on instances you
did not list.

**Not confirmed.** Nothing was run against a live ServiceNow instance.

- ServiceNow's pages name these tables, their columns and the read-only role,
  but do not say in so many words that the Table API serves them. If an
  instance refuses, the status says which table.
- If a ServiceNow release names a column differently, the instance leaves it
  out without saying so, and the check reads that value as "not set". Only
  each record's `sys_id` is required. The effect would be a blank state or
  version in the status, and a weaker fingerprint, not a wrong one.
- ServiceNow applies the page size before its access rules, so a page can come
  back short while more records remain. The check therefore stops only at an
  empty page. If the account could not read 100 agent records in a row, the
  records after them would not be seen. The `sn_aia.viewer` role can read them
  all.
- The sign-in always sends a `scope` field, empty unless you set `scope`. The
  OAuth standard says an empty field counts as left out; we could not confirm
  that ServiceNow treats it so.
- Government and other separately hosted instances whose address does not end
  in `.service-now.com` are refused in the settings.
- The agents ServiceNow ships ready-made are records in the same table as your
  own, so they are listed too and will appear on the "not enrolled" list. The
  check does not guess which of them can run.
- `max_agents` counts every record this check reads (agents, settings records,
  versions and tool links), not agents alone. Raise it if a large instance is
  refused for listing too many.

## The Workday check (`workday`)

**Reads:** the agent definitions registered in your tenant's Agent System of
Record, with one call through Workday's Agent Gateway:
`GET https://<region>.agent.workday.com/asor/v1/agentDefinition`, sent with
the header `wd-agent-tenant-alias: <tenant>`.

**Settings:**

- `region`: the Agent Gateway region that hosts your tenant. One of `us`,
  `eu`, `uk`, `ca`, `au`, `sg`, `in`, `jp`.
- `tenant`: your tenant alias (normally the tenant name).
- `client_id_env`, `client_secret_env` and `refresh_token_env`: the names of
  the environment variables that hold the API client's id, its secret, and the
  refresh token.

One section covers one tenant.

**Permission to grant,** in Workday:

1. Create an integration system user (task *Create Integration System User*),
   or reuse one, and put it in a security group that can view the
   **Setup: Agents** domain in the Agent System of Record functional area.
2. Run the task *Register API Client for Integrations*: choose **Agent System
   of Record** as the scope (functional area) and tick *Include Workday Owned
   Scopes*. Save the client ID and client secret it shows.
3. On that API client choose Related Actions > *Manage Refresh Tokens*, pick
   the integration system user, and generate a refresh token.

The check signs in with the refresh token (Workday documents no sign-in for
this API that uses a client id and secret alone). It asks for a new access
token at each check and keeps it only for that check.

**What counts as a change:** the definition's name, version label, address
(`url`), provider, platform, external agent and tenant ids, description,
capabilities, input and output types, its skills, and its Workday set-up: which
Workday resources each skill may use, and whether a skill runs on its own
("ambient") or on behalf of a person ("delegate"). Descriptions, skills and
resource lists are turned into fingerprints as they are read and are never
kept. The overview message, icon and documentation link are left out.

**Cannot see:** whether an agent is activated or deactivated, which of its
skills are switched on, and which security groups it is available to. Those
are set in the Agent Management Hub and Workday offers no call to read them, so
the state is shown blank. Workday also gives no "last changed" time and nothing
about what an agent did.

**Not confirmed.** Nothing was run against a live Workday tenant.

- Workday documents no way to read this list in parts. Its answer carries a
  count, and the check requires the count to equal the number of definitions
  sent. If Workday ever sends only the first part of a long list, the check
  fails with a plain message instead of treating the part as the whole. Tell
  us if you see this.
- If Workday lists the same definition id twice (its pages suggest the id may
  link several versions of one agent), the check fails instead of picking one.
- We could not confirm whether Workday replaces the refresh token each time it
  is used. The check never stores a token, so if yours is replaced on use the
  second check will be refused. Workday's *Register API Client for
  Integrations* task has a *Non-Expiring Refresh Tokens* option; use it.
- We could not confirm the exact name of the permission the security group
  needs on the Setup: Agents domain. Workday's API description says only that
  the list is "secured by" that domain.
- Only the eight regions above are accepted, as Workday lists them.

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
- **Direct connections only.** The checks connect straight to each platform and
  do not use an outbound proxy. If your installation restricts outbound
  connections, allow `login.microsoftonline.com`, `graph.microsoft.com`, your
  `<resource>.services.ai.azure.com` and your `<name>.crm*.dynamics.com`
  hosts, and for the other platforms your `<instance>.service-now.com` hosts
  and `<region>.agent.workday.com`. A resource reachable only through a
  private endpoint is refused unless you have allowed private addresses for
  fetches.
- **Client secrets only.** Certificates and managed identities are not
  supported for sign-in. (The Workday check also needs a refresh token.)
- **ServiceNow and Workday have not been run against a live instance or
  tenant either.** Both follow the vendors' published pages (listed below),
  and both have points the pages leave open; each section above says which
  under "Not confirmed".
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
| nothing at the address (HTTP 404) | Check the project endpoint, the environment or instance address, or the region. |
| the platform listed more than N agents / did not end within N pages | Raise `max_agents` or `max_pages` if the number is expected. |
| the answer was not in the expected form | The platform's answer did not match its documentation. Nothing from that check was used; report it. |
| network rules do not allow connections | Allow the hosts listed under "Limits". |
| ServiceNow sent records it had already sent (a repeat) | The instance did not move on to the next page. Nothing from that check was used; report it. |
| Workday's count of agent definitions does not match the number it sent | Workday sent only part of its list. Nothing from that check was used; see "Not confirmed" in the Workday section and report it. |
| Workday refused this check's sign-in | Check the region, tenant, client id, client secret and refresh token. Generate a new refresh token if the old one was replaced or has expired. |

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

## ServiceNow pages this check follows

- Sign-in (OAuth 2.0 client credentials, `POST /oauth_token.do`): https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials-grant-workflow.html
- Setting up the client-credentials integration and its roles: https://www.servicenow.com/docs/r/platform-security/authentication/configure-an-oauth-client-credential-grant.html
- The property that turns the client-credentials sign-in on: https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials.html
- The Table API (`sysparm_fields`, `sysparm_limit`, `sysparm_offset`, sorting, and the page size being applied before access rules): https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
- The AI agent tables and the `sn_aia.viewer` role: https://www.servicenow.com/docs/r/intelligent-experiences/na-aia-reference.html
- The columns of those tables ("Field Mapping" and "Coalesce Keys" in the ServiceNow SDK reference): https://servicenow.github.io/sdk/api/aiagent-api
- The record id (`sys_id`): https://www.servicenow.com/docs/r/platform-administration/c_UniqueRecordIdentifier.html
- Custom instance URLs, and why they are not accepted: https://www.servicenow.com/docs/r/platform-security/authentication/custom-url.html

## Workday pages this check follows

- The Agent System of Record endpoint, its token endpoint and the `wd-agent-tenant-alias` header: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/external-agents/register-and-authenticate-external-agents.html
- The Agent Gateway and its regional addresses: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/workday-agent-gateway-for-partner-agents.html
- The integration system user, its API client and the refresh-token sign-in: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/external-agents/connect-custom-agents-to-external-agents-using-a2a.html
- The other documented sign-in, which needs a person (authorization code): https://doc.workday.com/admin-guide/en-us/workday-ai/agents/external-agents/register-an-external-agent-using-the-asor-api.html
- Token lifetimes: https://doc.workday.com/admin-guide/en-us/workday-ai/agents/external-agents/concept--external-agent-asu-considerations.html
- The API description (the list answers with `total` and `data`; the fields of a definition): https://workday.github.io/asor/versions/v1.2.json and https://workday.github.io/asor/versions/v1.2.html
- A sample definition and answer: https://developer.workday.com/documentation/GUID-371cf3b1-eb6d-457d-8ba3-b36d5dbcf633/SampleASORAPIAgentDefinition
