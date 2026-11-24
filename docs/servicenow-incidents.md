# Send Second Shift incidents to ServiceNow

Second Shift queues an incident when it blocks an enrolled agent after
repeated rule violations (a single refused action is not an incident),
detects high-severity drift outside the learning period, marks an agent
missing from its platform, or arms the emergency stop. It
resolves the corresponding incident after release, acknowledgement, a
successful sighting, or clearing the stop in the dashboard.

An incident covers one active episode of a cause. Repeated reports for the same
blocked agent, drift finding, platform absence or deployment stop coalesce.
If the cause returns after resolution, a new episode can start. Titles and
notes use fixed language. The incident includes an opaque correlation ID and,
for an agent, a short opaque reference. The queue and outgoing requests omit
agent prompts, outputs, raw tool details and operator-supplied stop reasons.

## Set up ServiceNow

1. In a test instance, enable inbound OAuth client credentials with
   `glide.oauth.inbound.client.credential.grant_type.enabled`. Create an inbound
   client-credential integration and set its OAuth Application User. ServiceNow
   lists the setup roles `oauth_admin`, `mi_admin` and `admin`.
   [Enable the grant](https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials.html) ·
   [Configure the integration](https://www.servicenow.com/docs/r/platform-security/authentication/configure-an-oauth-client-credential-grant.html)
2. Give that application's user enough permission to read, create and update
   its incidents through the Table API. ServiceNow documents `sn_incident_write`
   and `itil` for incident creation and resolution. Use the narrower role if
   available and verify the API access controls, row access and field access in
   your instance. Second Shift resolves incidents and leaves final closure to
   your own workflow. The documented manual closure roles are `itil_admin` and
   `admin`.
   [Create an incident](https://www.servicenow.com/docs/r/it-service-management/incident-management/create-an-incident.html) ·
   [Resolve and close an incident](https://www.servicenow.com/docs/r/it-service-management/incident-management/resolve-and-close-an-incident.html)
3. Add a custom String field to the Incident table with the element name
   `u_second_shift_correlation_id` and room for at least 32 characters.
   Create a **unique index** on it before enabling delivery. Allow the
   integration user to set it at create time, filter by it, and read it back.
   Protect the value from edits. The unique index is required for safe retries
   when the network loses a successful creation response.
   [Create a table index](https://www.servicenow.com/docs/r/platform-administration/table-administration-and-data-management/t_CreateCustomIndex.html)
4. Confirm the instance's stored values for **State** Resolved and Closed and
   select a valid stored **Resolution code** for automated resolutions.
   Review incident data policies for other mandatory fields. If your instance
   requires Caller, provide the `sys_id` of an appropriate integration caller.
   [Incident form fields](https://www.servicenow.com/docs/r/it-service-management/incident-management/create-an-incident.html) ·
   [Resolve and close an incident](https://www.servicenow.com/docs/r/it-service-management/incident-management/resolve-and-close-an-incident.html)

## Configure Second Shift

Store the integration credentials in secret-backed environment variables.
Reference their names in installation settings.

```toml
[servicenow_incidents]
enabled = true
instance = "https://your-instance.service-now.com"
client_id_env = "SECOND_SHIFT_SERVICENOW_CLIENT_ID"
client_secret_env = "SECOND_SHIFT_SERVICENOW_CLIENT_SECRET"
close_code = "<stored resolution code from your instance>"
resolved_state = "6"
closed_state = "7"
# caller_id = "<32-character record ID of the integration caller>"
```

Use the instance's `service-now.com` address. Configured custom domains and
addresses with a path are refused. Keep the dashboard running to drain the
queue. Incident delivery has its own enable switch. It can run alongside
Teams and email alerts. Check **Alert delivery** on the Outside agents
page for pending deliveries and retries.

If ServiceNow is unavailable, the governance action still runs and the
incident stays queued. Each retry first searches for the correlation ID
before attempting creation. The queue waits 30 seconds after an unsuccessful
attempt and backs off up to 15 minutes between retries. Its separate sender
lock keeps concurrent workers from sending the same queued intent. Keep
`servicenow_incidents.json` in the data backup so the dashboard can resume
delivery after a restart. Changing the target instance leaves old queued
incidents bound to their original destination.

## Requests and verification

| Operation | Request and fields | ServiceNow reference |
| --- | --- | --- |
| Obtain a token | `POST /oauth_token.do` with the client credentials grant and form fields `grant_type`, `client_id`, `client_secret` and optional `scope`. Send the returned `access_token` as a bearer. | [Client credentials grant workflow](https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials-grant-workflow.html) |
| Look up an incident | `GET /api/now/table/incident` filtered with `sysparm_query` and `sysparm_limit`, or `GET /api/now/table/incident/{sys_id}`. Read only `sys_id`, `state` and the custom correlation field through `sysparm_fields`, with `sysparm_display_value=false`. | [Table API](https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html) |
| Create | `POST /api/now/table/incident` with `short_description`, `description`, the custom correlation field, and `caller_id` if configured. | [Table API incident example](https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html) |
| Resolve | `PATCH /api/now/table/incident/{sys_id}` with `state`, `close_code` and `close_notes`. Success requires the returned state to be Resolved or Closed. The integration never transitions an incident to Closed. | [Table API](https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html) · [Resolution fields](https://www.servicenow.com/docs/r/it-service-management/incident-management/resolve-and-close-an-incident.html) |

ServiceNow's support article identifies `6` and `7` as its resolved/closed
`state` values and distinguishes that field from `incident_state`. The kit
uses `6` for Resolved and `7` for Closed by default. Verify both values in
your instance if the choices have been customized. The public documentation
does not establish a universal stored `close_code` for this integration.
Second Shift requires the actual choice value from your instance. Table
and field ACLs, other required fields, and business-rule behavior also
depend on the instance. Automated checks use a mock instance, and no live
ServiceNow tenant was tested.
[ServiceNow support KB0727802](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0727802)
