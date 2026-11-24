# Approve in Microsoft Teams

When an agent's risky action, or a request for an access key, waits for a
person, Second Shift can send the people who may decide it a card in Microsoft
Teams. The card shows the request with **Approve** and **Reject** buttons.
Pressing one decides the request by exactly the same rules as the **Approvals**
page, and the card then shows who decided and when.

Nothing in this guide has been tested in a real Teams tenant. Everything was
checked against stand-ins for Microsoft's services and against Microsoft's
documentation (see [What was not confirmed](#what-was-not-confirmed)). Try it
with the test card (step 6) before you rely on it.

Approvals in Teams are off until you turn them on. Nothing is sent to Teams
before that.

## How it works

- You register an **Azure Bot** and a small **Teams app** that points at Second
  Shift. Second Shift is the bot: Teams sends it a signed request when someone
  presses a button.
- Second Shift checks every request against Microsoft's published signing keys
  before it looks at anything else. A request that does not check out is
  refused and nothing is decided.
- A button press decides the request only if the person has the **approve**
  permission, may open that request, and meets the same rules as on the web
  page (see [What a card does](#what-a-card-does)).
- The bot does nothing else. It does not run tasks or answer questions.

## 1. Create the Azure Bot (single tenant)

Microsoft stopped allowing new multi-tenant Azure Bots after 31 July 2025, so
Second Shift supports a **single-tenant** bot: one that belongs to your own
Microsoft Entra tenant.

1. In the Azure portal, create an **Azure Bot** resource. Under **Type of app**
   choose **Single Tenant** and let it create a new Microsoft app ID (or use an
   app registration you already made for the bot).
2. Open the bot's **Configuration** page. Copy the **Microsoft App ID** and the
   **App Tenant ID**. Set **Messaging endpoint** to
   `https://<your Second Shift host>/webhook/teams`.
3. Next to **Manage Password**, create a **client secret** and copy its
   **Value** now (not its id). Azure shows the value once.
4. Open **Channels**, add **Microsoft Teams** and accept the terms.

Use a GCC, GCC High or DoD Teams cloud? Also set `service_url` (step 3).

## 2. Give Second Shift the secret

Put the client secret in an environment variable on the server that runs
Second Shift (or a mounted secret file of the same name). The settings hold the
**name** of that variable, never the secret. A secret is never logged, shown,
saved or returned by any page.

```
TEAMS_BOT_SECRET=<the client secret value>
```

## 3. Settings

In `config.toml`:

```toml
[teams]
enabled = true                       # off by default
app_id = "00000000-0000-0000-0000-000000000000"   # Microsoft App ID
app_secret_env = "TEAMS_BOT_SECRET"  # the NAME of the variable that holds the secret
tenant_id = "11111111-1111-1111-1111-111111111111" # your Entra tenant id
allowed_tenants = []                 # extra tenants to accept; tenant_id is always accepted
allowed_users = []                   # optional: only these Entra object ids may press a button
channel_id = ""                      # optional: also post each request to this Teams channel
service_url = ""                     # optional: your Teams cloud's Bot Connector address
```

- Teams is ready only when `enabled`, `app_id`, `tenant_id` and the secret are
  all set. Anything missing is named in the status answer (step 6).
- A request from any other tenant is ignored. `allowed_users` is empty by
  default, which means anyone whose Teams account is recognised (step 5) may
  press a button; list object ids to narrow it further.
- `channel_id` is the Teams channel id, which looks like
  `19:abc123...@thread.tacv2`. In Teams, open the channel's menu, choose **Get
  link to channel** and copy the part after `/channel/`, with `%3a` written as
  `:` and `%40` as `@`, up to the next `/`. Only requests about outside agents
  (an agent's action or an access-key request) go to the channel, because a
  channel is read by many people. Anyone who presses a button there is still
  checked as a person.
- `service_url` is only used to start a chat or channel post before the bot
  has seen a message from that place. Leave it empty for the public cloud
  (`https://smba.trafficmanager.net/teams/`). Microsoft's list for other
  clouds: GCC `https://smba.infra.gcc.teams.microsoft.com/teams`, GCC High
  `https://smba.infra.gov.teams.microsoft.us/teams`, DoD
  `https://smba.infra.dod.teams.microsoft.us/teams`.

## 4. Upload and install the Teams app

Build the app package, which holds a manifest and two icons and no secret:

```
python teams-app/build_package.py --bot-app-id <Microsoft App ID> --hostname secondshift.contoso.com
```

This writes `second-shift-teams.zip`. The files it is built from are in
`teams-app/`: `manifest.template.json`, `color.png` (192 by 192) and
`outline.png` (32 by 32). Change the icons if you like; keep those sizes.

An administrator uploads it and makes it available:

1. In the **Teams admin center** open **Teams apps > Manage apps**, choose
   **Upload new app** and select the zip. The app is usually available to
   people after a few hours.
2. Decide who may use it under **Teams apps > Permission policies**.
3. To put it in front of people without asking each of them to add it, either
   open the app in **Manage apps** and choose **Edit installs** (or **Users and
   groups > Installs > Install app**) and pick the people or groups, or add it
   under **Installed apps** in a **Setup policy** and assign that policy to a
   group.

A person can also add the app themselves from **Apps > Built for your org**.
The bot can only start a chat with someone who has the app installed in their
personal scope. For the channel, add the app to that channel's team.

## 5. Who gets a card, and linking Teams accounts

A card goes to a person when all of these hold:

- their role allows deciding approvals (the **approve** permission: approver,
  operator, governance lead or administrator, or a custom role that has it);
- they can open that request on the Approvals page. An outside agent's request
  or an access-key request can be opened by everyone who holds a role. Any
  other request is private to its owner and to people granted access, and its
  card is sent only to them;
- Second Shift knows their Teams account and has a chat with them;
- the request does not have to be left to someone else (a person who asked for
  a high-risk action is not sent a card they could not approve).

Second Shift knows a Teams account in one of three ways:

- **Company sign-in with Entra is on (the usual case).** Second Shift records
  each person's Entra object id when they sign in. A person who has signed in
  once is recognised in Teams with nothing to set up. They only need to have
  the app installed and to have sent the bot any message once (or have been
  added by an administrator, below), so that Second Shift has a chat to post
  into.
- **An administrator links an account by hand** with the person's Entra object
  id or user principal name (the sign-in address, such as `alice@contoso.com`):

  ```
  POST /api/v1/teams/links   {"teams_id": "<object id or sign-in address>", "principal": "<Second Shift user>"}
  GET  /api/v1/teams/links
  DELETE /api/v1/teams/links/<teams_id>
  ```

  An object id never changes, so use it when you can. A link made with a
  sign-in address is tied to the person's object id the first time they message
  the bot. A card can be started in a new chat only for a link made with an
  object id, and only if the person has the app installed.
- **Company sign-in is off.** An administrator issues a one-time code and the
  person sends the bot `link <code>` in a personal chat. The code lasts 15
  minutes, works once, is shown once, and is never accepted while Entra sign-in
  is on.

  ```
  POST /api/v1/teams/link-codes   {"principal": "<Second Shift user>"}
  ```

A person checks their own state with `GET /api/v1/teams/me`.

People who only hold their role through an app role in their Entra sign-in
token, and have no role assigned in Second Shift itself, cannot receive or
decide cards in Teams: their role exists only inside their own browser
session. Assign them a role in Second Shift to include them.

## 6. Check that it works

An administrator can look at the setup at any time and send a test card:

```
GET  /api/v1/teams        whether Teams is set up, what is missing, in words
POST /api/v1/teams/test   checks that Microsoft accepts the app id, secret and tenant,
                          then sends a test card to the administrator's own Teams chat
                          and to the channel if one is set
```

Neither answer holds a secret. The test card has no buttons and decides
nothing.

## What a card shows

- what is asked (the target and what it will do), who or what asked, the
  risk, and the time to decide by;
- the request's **fingerprint** (the first characters of its approval
  binding). The buttons carry the full binding, so a decision applies only to
  exactly what the card describes;
- the agent's own description of the action, only when
  `[external_agents] show_request_detail` is on. It is the agent's claim, not a
  checked fact;
- a request that carries an exact command shows "The exact command is shown on
  the Approvals page". Such a request can be rejected in Teams but approved
  only on the page;
- for **high** and **critical** risk, a toggle "I have read what this action
  will do" (and, for critical, a box to type `APPROVE`), as the Approvals page
  asks;
- if `[dashboard] public_url` is set, an **Open in Second Shift** button.

## What a card does

Approve and Reject go through the same decision path as the Approvals page:

- the person needs the approve permission and must be able to open the request;
- the card's binding must match the current request, and the request must not
  have expired or changed;
- the person who asked for a high-risk action may be told to leave it to
  someone else, as on the page;
- a high or critical risk approval is refused until the toggle (and the typed
  word for critical risk) is given. The server checks this, not the card;
- a request for a settings change is decided on the page only;
- the decision is written to the signed audit record, with Teams noted as where
  it came from.

Refusals come back on the card in plain words and leave the buttons in place
when the request is still waiting. After a decision, every copy of the card
Second Shift posted is updated to show who decided and when, whether the
decision was made in Teams or on the page. Pressing a button on a card for a
request already decided elsewhere shows how it was decided and offers no
buttons. There is no undo from Teams.

If Teams delivers the same button press twice, the second is recognised and
shows where the request stands; it does not decide twice.

## Limits

- Teams cards cannot be updated if Teams refuses the update; the card then
  says the request was already decided when someone presses it.
- A request can wait in Teams for people who never installed the app. They
  still see it on the Approvals page.
- Pages in Second Shift for setting this up are not part of this change; use
  the API above.

## What was not confirmed

Checked against Microsoft Learn:

- Bot Connector authentication (token endpoint for a single-tenant bot,
  signing-key document, issuer, audience, expiry, key refresh):
  <https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication>
- Single-tenant bots; multi-tenant creation ended 31 July 2025:
  <https://learn.microsoft.com/azure/bot-service/bot-service-quickstart-registration>
- `Action.Execute`, the `adaptiveCard/action` invoke and its response:
  <https://learn.microsoft.com/adaptive-cards/authoring-cards/universal-action-model>
  and
  <https://learn.microsoft.com/microsoftteams/platform/task-modules-and-cards/cards/universal-actions-for-adaptive-cards/work-with-universal-actions-for-adaptive-cards>
- Proactive messages, creating a chat with a person's Entra object id, posting
  to a channel, updating a posted message:
  <https://learn.microsoft.com/microsoftteams/platform/bots/how-to/conversations/send-proactive-messages>
  and
  <https://learn.microsoft.com/microsoftteams/platform/resources/bot-v3/bot-conversations/bots-conv-proactive>
- Installing an app for people: <https://learn.microsoft.com/microsoftteams/install-teams-apps>
  and <https://learn.microsoft.com/microsoftteams/teams-custom-app-policies-and-settings>

Not confirmed, and why it matters:

- **Token issuer for a single-tenant bot.** Microsoft's page lists only
  `https://api.botframework.com` for requests from the Bot Connector. Second
  Shift accepts only that and refuses anything else. If a real tenant sends a
  different issuer, requests would be refused (safe, but the bot would not
  work).
- **Pre-installed apps and the first chat.** It is not confirmed that installing
  the app for people through a setup policy or Graph makes Teams send the bot an
  install event. Second Shift handles the install events it knows
  (`conversationUpdate`, `installationUpdate`), and otherwise starts the chat
  itself from an object id an administrator linked. That is refused with
  "forbidden" when the app is not installed for the person.
- **A person's user principal name.** Second Shift asks Teams for the member
  record (`GET /v3/conversations/{id}/members/{userId}`) to read the
  `userPrincipalName`. The endpoint is documented; the field name in a real
  response was not seen.
- **Whether the card returned to the person who pressed a button is also shown
  to everyone else** in a shared chat or channel. Second Shift therefore also
  updates the posted message itself.
- **Card version.** Cards use Adaptive Cards 1.5, which Teams asks for with
  `Action.Execute`. Microsoft's general page says 1.4 is the minimum.
- **Manifest version.** The template uses Teams manifest schema 1.25; newer
  versions exist. Teams admin center validates the package when you upload it.
- **The role of someone who signs in only through an Entra app role** is not
  known to Second Shift outside their browser session (see step 5).
