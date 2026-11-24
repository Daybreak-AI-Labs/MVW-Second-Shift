# Alerts to Microsoft Teams and email

Second Shift can tell your team when something needs attention: an outside
agent changed since its approved baseline, an agent is waiting for an
approval, or everything was stopped. An alert can go to a Microsoft Teams
channel, to an email address, or to both.

Alerts are off until you turn them on. Nothing is sent to any other service.

## 1. Create the Teams webhook

Microsoft retired the old "Incoming Webhook" connector in May 2026. The
supported way to post into a channel is a workflow in the Teams **Workflows**
app.

1. In Teams, open the channel that should receive alerts.
2. Select **More options (...)** next to the channel, then **Workflows**.
3. Choose the template **Send webhook alerts to a channel**.
4. Confirm the team and channel, then select **Save**.
5. Copy the webhook address the workflow shows.

Use that template and not the "from specific people" or "from people in an
org" ones. Each template accepts a different kind of caller; those two are for
signed-in people in your organisation, and Second Shift posts without signing
in.

Treat the address as a password. Anyone who has it can post to your channel.
Second Shift never shows it, logs it or returns it; the status answer below
only says whether one is set.

The workflow belongs to the person who created it. If that person leaves it
can stop working, so add a co-owner in Power Automate.

## 2. Settings

Settings live in `config.toml`. The two secrets, the Teams address and the
mail password, can come from the environment instead.

```toml
[alerts]
enabled = true                    # or set MAVERICK_ALERTS=1
backends = ["teams", "email"]     # where alerts go, in this order

[notifications]
teams_webhook = "https://..."     # or set TEAMS_NOTIFY_WEBHOOK_URL instead

[notifications.email]
host = "smtp.example.com"
port = 587
tls = "starttls"                  # starttls (default) | ssl | none
user = "alerts@example.com"
password = "..."                  # or set MAVERICK_SMTP_PASSWORD instead
from_address = "Second Shift <alerts@example.com>"
to = "ops@example.com"            # or a list: ["ops@example.com", "security@example.com"]
```

- **Channels.** `backends` may name `teams`, `email` or both. Leave it out and
  alerts go to the single `[notifications] backend` (`teams`, `email` or
  `none`, which is the default). Write `backends = ["none"]` to send alerts
  nowhere.
- **Teams address.** A saved `teams_webhook` wins over
  `TEAMS_NOTIFY_WEBHOOK_URL`. Keeping it in the environment keeps the secret
  out of the settings file. It must start with `https://`.
- **Email.** `to` is who receives alerts. `host` and `from_address` name the
  mail server and the sender. Without them, alerts use the mail account the
  product already sends invitations from (`EMAIL_USER` and
  `EMAIL_APP_PASSWORD`). The message is plain text.
- **Removed channels.** `ntfy`, `pushover`, `discord` and `slack` are no
  longer channels. In `[alerts] backends` such a name is ignored with a
  warning in the log; a notification addressed to one is recorded as not sent.
  A list that names only removed channels sends nowhere; it does not fall back.

Second Shift connects to Teams directly and only to a public internet
address. If your network only allows listed destinations, add the host of your
webhook address to the allowed hosts. A system-wide web proxy is not used.

## 3. Test delivery

An administrator can send a test at any time, whether or not alerts are on:

```bash
curl -X POST https://<your Second Shift address>/api/v1/alerts/test \
  -H "Authorization: Bearer <access token>"
```

```json
{
  "enabled": true,
  "sent": true,
  "results": {"teams": "sent", "email": "The mail server did not accept the user name and password."},
  "message": "The test reached teams but not email."
}
```

Each channel answers `sent` or says in plain words why not. The same test is
available in code as `maverick.ops_alert.send_test()`.

Anyone who can view the product can read how delivery is set up:

```bash
curl https://<your Second Shift address>/api/v1/alerts \
  -H "Authorization: Bearer <access token>"
```

```json
{
  "enabled": true,
  "channels": [
    {"channel": "teams", "ready": true, "problem": "", "webhook_set": true},
    {"channel": "email", "ready": true, "problem": "", "recipient": "ops@example.com"}
  ],
  "ignored": [],
  "available": ["teams", "email"]
}
```

`sent` means the service accepted the message. For Teams it means the workflow
was started; if the workflow then fails (it was turned off, or its owner lost
access to the channel), Teams does not tell Second Shift. Check the channel
after the first test, and the workflow's run history in Power Automate if
nothing arrives.

## 4. What an alert looks like

In Teams, a card posted by the Workflows bot with a bold title and the text
below it:

> **Second Shift ALERT: agent_drift.detected**
>
> helpdesk has moved away from its approved baseline. It used a tool it had
> not used before: export_records.

By email, the subject is the title and the body is the same text:

```text
Subject: Second Shift ALERT: agent_drift.detected

helpdesk has moved away from its approved baseline. It used a tool it had
not used before: export_records.
```

The test message is titled **Second Shift test alert** and says it is a test.

Good to know:

- An alert is sent once to each channel. A failed send is not retried.
- Sending waits for each channel to answer. A step of the Teams request is
  given up after 10 seconds and a step of the mail conversation after 15.
- A very long alert is shortened for Teams, which limits a message to 28 KB.
- Teams limits how often a webhook may be used (four requests a second).
- In a Teams card, square brackets in the text are shown as round ones, so
  that text chosen by an agent can never appear as a link.

## Microsoft pages this is built on

- [Retirement of Office 365 connectors within Microsoft Teams](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/)
  (Microsoft 365 Developer Blog): connectors were switched off between
  18 and 22 May 2026; use Workflows.
- [Create Incoming Webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
  (Microsoft Learn): creating the workflow, the 28 KB limit and the rate limit.
- [Microsoft Teams connector: When a Teams webhook request is received](https://learn.microsoft.com/en-us/connectors/teams/#microsoft-teams-webhook)
  (Microsoft Learn): the request body, a `message` holding Adaptive Card
  attachments.
- [Create and send messages](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using#send-adaptive-cards-using-an-incoming-webhook)
  (Microsoft Learn): sending an Adaptive Card to a webhook.
- [Send messages in Teams using incoming webhooks](https://support.microsoft.com/en-us/office/send-messages-in-teams-using-incoming-webhooks-323660ec-12ca-40b1-a1d3-a3df47e808c4)
  (Microsoft Support): the templates and which callers each accepts.
- [Format cards in Teams](https://learn.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/cards-format)
  and [Designing Adaptive Cards for your Teams app](https://learn.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/design-effective-cards)
  (Microsoft Learn): Markdown in card text, line breaks and wrapping.
