# Copilot Studio gate

This turns on Second Shift as the "external threat detection" service for
Microsoft Copilot Studio. Once a Power Platform administrator points an
environment at Second Shift, every time an agent in that environment is about
to call a tool, Copilot Studio asks Second Shift first and Second Shift
answers allow or block. You do not wire each agent by hand.

**Nothing here has been tested against a real Microsoft tenant.** It was built
to Microsoft's two pages for this feature and tested with a stand-in for
Microsoft's sign-in keys. Expect to adjust it on first contact with a real
tenant, and report what differs.

Microsoft's pages (both describe a preview feature that may change):

- [Build a runtime threat detection system for Copilot Studio agents](https://learn.microsoft.com/microsoft-copilot-studio/external-security-webhooks-interface-developers) (the contract Second Shift follows)
- [Enable external threat detection and protection for Copilot Studio custom agents](https://learn.microsoft.com/microsoft-copilot-studio/external-security-provider) (the administrator's side)

## What it does

Copilot Studio makes two calls to Second Shift, under `/copilot-studio/`:

| Call | What Second Shift answers |
| --- | --- |
| `POST /copilot-studio/validate` | `{"isSuccessful": true, "status": "OK"}` only when Second Shift can make decisions now: settings readable, the gate turned on, and outside-agent governance on. Otherwise 503 with a plain message. Power Platform admin center calls it when you save the setup. |
| `POST /copilot-studio/analyze-tool-execution` | `{"blockAction": false}` to allow, or `{"blockAction": true, "reasonCode": N, "reason": "..."}` to block. The reason is shown to the person in the chat. |

Both calls carry a Microsoft Entra access token (see "How the token is
checked"). Anything else gets 401 with Microsoft's error body
(`errorCode`, `message`, `httpStatus`). Unknown fields in a request and any
`api-version` value are accepted, as Microsoft asks. Requests over 1 MiB are
refused with 413.

For each tool call Second Shift:

1. Finds the agent. The settings map each Power Platform environment id to the
   environment's Dataverse host, so the agent's reference is
   `copilot_studio:<host>/<agent id>` in lower case, the same reference the
   Copilot Studio platform check writes. Enroll the agent with that
   reference (the platform checks page lists the agents it finds that are not enrolled) and it is found. Capital
   letters do not matter.
2. If the agent is enrolled, runs Second Shift's own screening for outside
   agents (the same one `/api/v1/external/screen` uses): enrollment limits on
   tools and risk, spend cutoff, containment, the emergency stop and the
   approval floor.
3. Answers:
   - allowed: `blockAction: false`.
   - refused, contained or emergency stop: `blockAction: true` and a reason
     that starts "Second Shift blocked this action:".
   - needs approval: `blockAction: true`, reason "This action needs approval
     in Second Shift (request #N). Ask again once it has been approved."

The tool's risk is the rating given to that tool name when the agent was
enrolled, else `default_risk`. Tool names are the names Copilot Studio shows
(for example "Send email"); the enrollment's tool list must use the same names.

Reason codes in a block answer: 101 refused by a rule, 102 agent contained, 103
emergency stop, 104 waiting for approval, 105 a person declined, 106 agent not
enrolled, 107 Second Shift could not decide.

### Approvals in a chat

A block that needs approval creates a request in the Second Shift approvals
queue (and alerts the people who approve, as for any outside agent). The person
in the chat sees the request number. When an approver says yes, the person
asks the agent again. Second Shift then allows that one call, when the same
agent asks for the same tool with the same inputs within
`approval_window_seconds` of the decision. That approval is used up by it: a
further ask makes a new request. Different inputs, a different tool or another
agent need their own approval. While a request waits, asking again does not
create more requests, and a declined request keeps blocking for the same
period. Containment, the emergency stop and a withdrawn enrollment still block
an approved call, and do not use the approval up.

### Agents that are not enrolled

`unenrolled = "allow"` (the default) lets the call through and records the
agent as seen, with its environment, agent id and tool name, so it can be
enrolled; the list is at `GET /api/v1/copilot-studio-gate` (needs the view
permission). `unenrolled = "block"` blocks it with "this agent is not enrolled
in Second Shift yet". An environment id that is not in the settings follows the
same choice.

### When Second Shift cannot decide

If the settings cannot be read or are not usable, the gate is turned off while
the environment is still pointed at Second Shift, or a record cannot be read, or the decision takes longer than 0.85 seconds,
Second Shift answers as `on_error` says: `"block"` (the default) or `"allow"`.
A value that is not one of those means block. If the audit log refuses to record a
decision, the call is blocked whatever `on_error` says.

What happens when Second Shift does not answer at all (down, slow, or a 401 or
503) is decided by Copilot Studio's own **Set error behavior** in Power
Platform admin center. Its default is to allow. Choose "Block the query" there
if you want a Second Shift outage to stop tool calls.

## What data Copilot Studio sends and what Second Shift keeps

Microsoft says each call shares the person's recent prompt, the recent chat
messages, the outputs of previous tools, the identity of the agent, the user,
the user's tenant and the trigger, and the tool with the agent's reasoning and
proposed inputs.

Second Shift reads those in memory to decide, and then forgets them. It never
stores, logs or audits the prompt, the chat history, the previous tool outputs,
the agent's reasoning or the input values, and no error message or response
repeats them. It keeps only:

- the environment id, the agent id, the tool name, the decision, the reason and
  the time (in the audit log, and for agents that are not enrolled, in the list
  above);
- for a tool that waits for approval, a keyed digest of the agent, tool and
  inputs (a one-way value; the inputs cannot be read back from it) and the
  request number, so the retry can be matched;
- the Entra user object id only when `record_user = true` (it is then added to
  the audit entries this gate writes).

What an approver sees: the tool name and the agent. Only when `[external_agents]
show_request_detail` is on, also a short summary of the proposed input values
(at most 8 values, 80 characters each, with secrets removed). With it off, the
approver sees names only.

## Setting it up

You need a Microsoft Entra tenant where you can register applications, a user
with the Power Platform Administrator role, and a public https address for
Second Shift that Microsoft can reach.

1. **Register the application.** In the Azure portal, Microsoft Entra ID, App
   registrations, create one (single tenant). Note its Application (client) ID
   and the tenant id. Microsoft also offers a script,
   `Create-CopilotWebhookApp.ps1`, that does steps 1 to 3 (parameters
   `TenantId`, `Endpoint`, `DisplayName`, `FICName`).
2. **Expose the address.** Under Expose an API, set the Application ID URI to
   Second Shift's origin, for example `https://second-shift.contoso.com`.
   Microsoft's page says the exposed scope must be the service's base URL and
   its example uses the origin without the path. Prefer version 2.0 tokens
   (set `accessTokenAcceptedVersion` to 2 in the manifest).
3. **Add the federated credential.** Certificates and secrets, Federated
   credentials, Add credential, scenario "Other issuer":
   - Issuer: `https://login.microsoftonline.com/<tenant id>/v2.0`
   - Type: Explicit subject identifier
   - Value: `/eid1/c/pub/t/<base64url tenant id>/a/m1WPnYRZpEaQKq1Cceg--g/<base64url endpoint link>`
     where the endpoint link is the address you give Power Platform admin
     center in step 5 (for example `https://second-shift.contoso.com/copilot-studio`).
     Microsoft's page gives PowerShell for the two encodings.
4. **Turn the gate on in Second Shift.** Add the settings below and restart or
   reload. Turn on outside-agent governance (`[external_agents] enable = true`)
   and enroll the agents (see "Agents" below).
5. **Point the environment at Second Shift.** Power Platform admin center,
   Security, Threat detection, Additional threat detection, choose the
   environment, Set up. Tick "Allow Copilot Studio to share data with a threat
   detection provider", enter the Application (client) ID from step 1, enter the
   endpoint link `https://<your address>/copilot-studio`, and choose **Set error
   behavior**. Save. Saving fails when `validate` fails or the Entra setup is
   wrong; the page shows the error to copy. Repeat for each environment: there
   is one setting per environment and none for a whole tenant.

### Settings

```toml
[external_agents]
enable = true                   # outside-agent governance must be on

[copilot_studio_gate]
enable = true                   # off by default; while off, decisions follow on_error
tenant_id = "11111111-2222-3333-4444-555555555555"
app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"   # the application id given to Power Platform admin center
audience = "https://second-shift.contoso.com"     # the Application ID URI from step 2
api_client_id = ""              # optional: the exposed API's own application id; version 2.0 tokens carry it as the audience
unenrolled = "allow"            # "allow" (record as seen) or "block"
on_error = "block"              # "block" or "allow", when Second Shift cannot decide
default_risk = "medium"         # risk of a tool the enrollment does not rate
approval_window_seconds = 900   # 60 to 3600: how long after a decision the retry may use it
record_user = false             # true keeps the Entra user object id in audit entries

[copilot_studio_gate.environments]
# Power Platform environment id = that environment's Dataverse host
"0c6b1c52-8a6e-4f0e-9a43-6a8f2b1d9c11" = "contoso.crm.dynamics.com"
```

A value that cannot be used (a bad id, host or word) makes Second Shift
answer 503 to `validate` and follow `on_error` for decisions until it is fixed.
Only public-cloud Dataverse hosts (`*.crm.dynamics.com`, `crm2` and so on) are
accepted, as in the platform check.

### Agents

Enroll each Copilot Studio agent as an outside agent of platform "Microsoft
Copilot Studio", with the external reference
`copilot_studio:<host>/<agent id>` (the platform checks page lists the agents
found there that are not enrolled), the tools it may call, written as Copilot
Studio names them, and a rating per tool (`Send email:high`). The agent id is
the `botid` of the agent in Dataverse; Microsoft's page calls it "ID of the
agent" and does not say more, so check it on the first real call.

## How the token is checked

Microsoft's developer page says the integration must use Microsoft Entra
authentication, expose a scope equal to the base URL, and "validate incoming
tokens", leaving authorization (an allow list of app ids, for example) to the
service. It does not name the token's claims. Second Shift therefore reads the
strict form of Microsoft's token pages
([access token claims](https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference),
[validate tokens](https://learn.microsoft.com/entra/identity-platform/access-tokens#validate-tokens))
and refuses a token unless all of these hold:

| Check | Rule |
| --- | --- |
| Signature | RS256, by a key in the tenant's published keys (`https://login.microsoftonline.com/<tenant id>/discovery/v2.0/keys`). No other algorithm, including "none". |
| Time | Not expired, and not before its start time. No allowance for clock differences, so keep the server clock right. |
| Issuer | `https://login.microsoftonline.com/<tenant id>/v2.0` (version 2.0) or `https://sts.windows.net/<tenant id>/` (version 1.0), for the configured tenant. |
| Audience | Equal to `audience`, or to `api_client_id` when set. Microsoft: in version 2.0 tokens the audience is the API's client id; in version 1.0 it can be the client id or the resource address. |
| Tenant | The `tid` claim is the configured tenant. |
| Caller | `azp` (version 2.0) or `appid` (version 1.0) equals `app_id`. Microsoft marks both as usable for authorization. |
| Kind | No `scp` claim. Microsoft says `scp` appears only on user tokens, and Copilot Studio calls as an application. |

A token that fails gets 401. If the tenant's keys cannot be fetched Second
Shift answers 503, never a decision. Keys are cached for five minutes and a
refresh for an unknown key id is allowed once every ten seconds.

Left open by Microsoft's pages: which of `azp`/`appid` and which audience form
Copilot Studio's token will carry (this is why both issuer and audience forms
are accepted, and each only in its strict form); whether the token has a
`roles` claim (not required here); whether the agent id in the request is the
Dataverse `botid`; and the Dataverse host for an environment, which the
request does not carry (hence the settings).

## Limits

- It is a preview feature of Copilot Studio. It may change, and Microsoft says
  preview features are not meant for production.
- Copilot Studio calls it only for agents that use generative orchestration. It
  skips classic agents, so they are not governed by this.
- One setting per environment, set by hand in Power Platform admin center.
  There is no tenant-wide switch and no way to script it, and a new
  environment needs it turned on again.
- Copilot Studio waits one second. Second Shift decides in well under that (on
  a development machine, 40 decisions with the audit log on took a median of
  9 ms and a longest of 23 ms) and gives up its own work at 0.85 seconds. The
  first call after a restart also fetches Microsoft's signing keys and can take
  longer; a saved `validate` call warms them.
- If Second Shift does not answer in time, Copilot Studio allows by default.
  Set its error behavior to block if you want the opposite.
- Microsoft says provider data-handling may differ from Microsoft's, including
  where data is processed. Second Shift keeps none of the conversation, but the
  data does leave Microsoft's service for yours. Disconnect the environment in
  Power Platform admin center to stop sharing.
- The gate decides only whether a tool call goes ahead. Everything a tool does
  afterwards is outside it.
- Fetching Microsoft's signing keys uses the same library the sign-in uses, not
  the outbound-call guard, and goes only to the fixed Microsoft address above.
