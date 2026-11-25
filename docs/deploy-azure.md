# Deploy Second Shift to Azure

This kit creates a public HTTPS Container App with Entra sign-in, a private
PostgreSQL Flexible Server, Azure Files, Key Vault, an image registry, and
Log Analytics in one Azure subscription. The service runs with one replica
and uses PostgreSQL row-level security. The app's records (enrolled agents,
trust, drift, platform checks, approvals cards, alerts, sign-in roles) are kept
in PostgreSQL. The settings saved from the Settings page, the signed audit log,
the emergency-stop file, browser sessions and Ekko's stores stay at
`/var/lib/second-shift` on Azure Files. The app keeps up to eight database
connections open for reuse (`SECOND_SHIFT_PG_POOL_SIZE`).

## 1. Prepare the subscription and vault

Use Azure public cloud, Azure CLI with Bicep, Docker with BuildKit, OpenSSL
and a PostgreSQL 17+ client. Use a deployment identity that can create role
assignments and retrieve deployment parameters from Key Vault
(`Microsoft.KeyVault/vaults/deploy/action`). For the database bootstrap, have
a workstation or jump host in or peered to the deployment virtual network.
A peered network also needs private DNS resolution for the server. Reserve
`10.70.0.0/16` or change the two subnet ranges in the template before deployment.

From the repository root in Bash, choose a lowercase app prefix (2–18 letters,
digits and single hyphens, starting with a letter and ending in a letter or
digit). Choose a globally unique vault name. Use a region that offers the
configured PostgreSQL SKU and Container Apps. Register any unregistered
providers for Container Apps, Container Registry, Network, PostgreSQL,
Storage, Key Vault, Managed Identity and Operational Insights.

```bash
az login
az account set --subscription '<subscription ID>'
rg='second-shift-prod'
region='eastus'
prefix='second-shift-prod'
vault='<unique vault name>'
operator=$(az ad signed-in-user show --query id -o tsv)

az group create -n "$rg" -l "$region"
az deployment group create -g "$rg" -n second-shift-vault \
  --template-file deploy/azure/vault.bicep \
  --parameters vaultName="$vault" operatorObjectId="$operator"
```

Use Bash with tracing off. This helper writes a secret supplied on standard
input to Key Vault without putting the value on the command line. Wait for
the operator's vault role to take effect before adding secrets. Set these
initial values once. Keep existing encryption and signing keys on redeploys.

```bash
set +x
store_secret() {
  local file result=0
  file=$(mktemp) || return
  cat > "$file" &&
    az keyvault secret set --vault-name "$vault" -n "$1" --file "$file" \
      --output none || result=$?
  rm -f -- "$file"
  return "$result"
}

random_secret() {
  local value
  value=$(openssl rand -hex 32) || return
  printf '%s' "$value" | store_secret "$1"
}

# Use a strong mixed-character PostgreSQL administrator password.
read -rsp 'PostgreSQL administrator password: ' value
printf '\n'
printf '%s' "$value" | store_secret postgres-admin-password
unset value

for name in oidc-session-secret dashboard-token deployment-encryption-key audit-signing-key; do
  random_secret "$name" || break
done
```

## 2. Create the network, database server, and registry

```bash
az deployment group create -g "$rg" -n second-shift-infra \
  --template-file deploy/azure/infra.bicep \
  --parameters prefix="$prefix" vaultName="$vault"

deployment_output() {
  az deployment group show -g "$rg" -n second-shift-infra \
    --query "properties.outputs.$1.value" -o tsv
}

origin=$(deployment_output publicOrigin)
pg_host=$(deployment_output postgresHost)
registry=$(deployment_output registry)
```

From the private workstation, connect as the bootstrap administrator with
`psql "host=$pg_host dbname=postgres user=secondshiftadmin sslmode=verify-full sslrootcert=system" -W`.
Run the following once. Set the service password using the interactive
`\password` prompts. A randomly generated hex password avoids URI escaping.

```sql
CREATE ROLE secondshift_service LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
\password secondshift_service
GRANT secondshift_service TO secondshiftadmin WITH SET TRUE;
CREATE DATABASE secondshift OWNER secondshift_service;
```

Back in the deployment shell, enter that service password to construct the
DSN. If you chose a password containing URI punctuation, enter its
percent-encoded form. The service role owns its database and can install the
schema and forced row-level policies on first boot.

```bash
read -rsp 'PostgreSQL service password: ' value
printf '\n'
printf 'postgresql://secondshift_service:%s@%s:5432/secondshift?sslmode=verify-full&sslrootcert=system' \
  "$value" "$pg_host" | store_secret postgres-dsn
unset value
```

## 3. Register sign-in and platform checks

Run the registration tool in the subscription's tenant after the vault and
public origin exist. Use an operator allowed to manage the app registration
and enterprise application and list and set secrets in the deployment vault.
On Linux, the tool passes the password to Azure CLI over standard input. It
prints the IDs and the admin consent link. It reuses the registration and
its existing vault secret on rerun.

```bash
deploy/azure/register-entra.sh "$origin" --vault "$vault"
# Copy the printed Application (client) ID for the app deployment below.
entra_client='<Application (client) ID>'
```

The registration is single-tenant and assignment is required. In Entra,
assign the first administrator `SecondShift.Admin` under **Enterprise
applications → Users and groups**. The same registration contains the seven
app roles listed in [Sign-in roles](sign-in-roles.md). To update a registration
the script did not create, supply `--app-id "$entra_client"`. If the sign-in
secret was previously set by hand, verify that it still belongs to that
registration before tagging the existing secret with `entra-app-id` in the
vault. [Application updates](https://learn.microsoft.com/en-us/graph/api/application-update?view=graph-rest-1.0)
and [enterprise app assignments](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal)

Add only the permission flags your deployment needs. Reruns preserve
previously requested permissions. Review and remove obsolete requests and
grants in Entra. The script requests permissions and prints a link. A tenant
administrator must grant consent.
[Admin consent](https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent)

| Flag | Graph application permission |
| --- | --- |
| `--read-app-assignments` | [`Application.Read.All`](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0) |
| `--read-group-members` | [`GroupMember.ReadBasic.All`](https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0) |
| `--search-people` | [`User.Read.All`](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0) for the owner picker |
| `--read-agent-identities` | [`AgentIdentity.Read.All`](https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0) for Entra Agent ID discovery |
| `--manage-agent-identities` | [`AgentIdentity.EnableDisable.All`](https://learn.microsoft.com/en-us/graph/api/agentidentity-update?view=graph-rest-1.0) for switching off an agent identity |

For [Microsoft 365 Copilot](m365-copilot.md), complete the Microsoft Entra SSO
registration in the Teams developer portal and rerun the script with
`--copilot-uri '<Application ID URI from the Teams developer portal>'`.
This configures the URI, the `SecondShift.Copilot.Read` scope, v2 access
tokens, the Teams consent redirect, and the authorized Enterprise token
store client. [Microsoft Entra SSO for Copilot](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-entra-sso)

To use the same registration for [Entra directory](entra-directory.md) or
Entra Agent ID checks, reference the printed tenant and client IDs and map
the corresponding credential environment variables to `oidc-client-secret`
in the vault. For other platforms, configure their separate access grants
only if you use those checks. [Platform checks](platform-checks.md) lists
the vendor roles and configuration. The factory's SharePoint permission
belongs on its separate runtime identity.

The script has been tested with a local Graph and vault mock. A tenant
administrator still needs to verify Graph permission availability, the
consent link, sign-in, and the Copilot token exchange with the registered URI.

Put the selected `[agent_watch.*]` tables in `config.toml` in the Azure Files
data folder using a controlled admin connection. These tables contain only
environment variable **names** for credentials. For example, reference
`SECOND_SHIFT_CHECK_TENANT_ID`, `SECOND_SHIFT_CHECK_CLIENT_ID`, and
`SECOND_SHIFT_CHECK_CLIENT_SECRET`. Supply the first two as non-secret
`platformSettings` and map the last to a Key Vault secret name in
`platformVaultReferences`. Use the same mechanism for each ServiceNow or
Workday client secret and the Workday refresh token. Set the selected
platforms and `enable = true` as documented. Keep the additional settings in
the app deployment parameters used for upgrades.

## 4. Build and deploy the app

Push a Linux AMD64 image to the registry as a principal with `AcrPush`. Keep
the release tag and use its digest in the app deployment.

```bash
login_server=$(az acr show -n "$registry" --query loginServer -o tsv)
release=$(git rev-parse --short HEAD)
az acr login -n "$registry"
docker build --platform linux/amd64 -f deploy/azure/Dockerfile \
  -t "$login_server/second-shift:$release" .
docker push "$login_server/second-shift:$release"
digest=$(az acr repository show -n "$registry" --image "second-shift:$release" --query digest -o tsv)
```

On a build host that uses a trusted TLS inspection CA, add
`--secret id=pip_ca,src=/path/to/ca-bundle.pem` to `docker build`.
BuildKit uses the bundle during package installation. On the first app
deployment, wait for any newly assigned identity roles to propagate and
retry the deployment if Key Vault or registry access is denied.

For production, record the Key Vault version IDs in an app parameter file as
the `secretVersions` map (keys are vault secret names). Use explicit versions
for the deployment encryption key and audit signing key. Versionless
references may cause Container Apps to restart the running revision
automatically after a rotation. Keep previous versions needed for recovery.

```bash
# Set entra_client to the sign-in app registration's application ID first.
az deployment group create -g "$rg" -n second-shift-app \
  --template-file deploy/azure/app.bicep \
  --parameters prefix="$prefix" vaultName="$vault" entraClientId="$entra_client" \
    image="second-shift@$digest"
curl --fail "$origin/livez"
curl --fail "$origin/readyz"
```

Include `--parameters @<parameter-file.json>` when supplying the versions or
platform settings. Secret values come from Key Vault references resolved by
the service's user-assigned identity. The application receives the resolved
values in its environment. The Key Vault RSA key wraps per-workspace data
keys. The deployment encryption key handles data sealed at deployment scope.
The Ed25519 audit key signs in-process. Protect the break-glass
`dashboard-token` as an administrator credential. The current command-line
entry point requires it to listen on all interfaces even when Entra is enabled.

Check browser sign-in, role assignments, a database write, and an audited
operation. Restart the deployed revision and check that the database and
file-backed state are still readable. Test the Azure Files mount ownership
and file locking before putting data on it. Ekko is off by default. Qualify
its local SQLite-backed workflows on your storage before enabling them.
Second Shift strips callback queries from its Uvicorn access log. Apply
the same rule to any ingress or proxy logs and restrict log access.

## 5. Enable approvals in Microsoft Teams (optional)

Create a dedicated single-tenant Entra registration for the bot in the
subscription's tenant and create its client secret. Save the client ID and
store the secret value as `teams-bot-secret` in the deployment vault. Use
the `store_secret` helper in step 1 with Bash tracing off.
[Single-tenant bot credentials](https://learn.microsoft.com/en-us/microsoftteams/platform/teams-sdk/teams/app-authentication/client-secret)

```bash
read -rsp 'Teams bot client secret: ' value
printf '\n'
printf '%s' "$value" | store_secret teams-bot-secret
unset value
teams_bot_client='<bot Application (client) ID>'
```

Include `enableTeams=true teamsBotAppId="$teams_bot_client"` after
`--parameters` on the app deployment in step 4. Register the
`Microsoft.BotService` provider if it is not already registered. The
template sets the bot's messaging endpoint to `$origin/webhook/teams`,
enables its Teams channel, and resolves the secret through the app's
user-assigned identity. When omitted, the Teams parameter defaults to off.
[Register a resource provider](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider)
[Azure Bot and Teams channel](https://learn.microsoft.com/en-us/azure/templates/microsoft.botservice/2022-09-15/botservices/channels)

In the deployment's `config.toml`, enable `[teams]`, use the bot client
ID and subscription tenant ID, and set
`app_secret_env = "SECOND_SHIFT_TEAMS_BOT_SECRET"`. See [Teams settings](teams-approvals.md#3-settings)
for the full table and optional channel settings. Build the package from
the repository root.

```bash
python3 teams-app/build_package.py --bot-app-id "$teams_bot_client" --hostname "${origin#https://}"
```

In the Teams admin center, open **Teams apps → Manage apps**, select
**Upload new app**, and upload `second-shift-teams.zip`. Make the app
available to the people who should receive cards and have them install it
or assign it with an app setup policy.
[Manage apps in the Teams admin center](https://learn.microsoft.com/en-us/microsoftteams/manage-apps)

The templates and Teams ZIP were checked locally. Confirm bot creation,
channel activation, app upload, and the test card and button press in a
real tenant before using it for approvals.

## Limit traffic at the gateway

For Internet-facing deployments, put Azure Front Door Premium with a WAF
policy in front of Container Apps. Restrict direct ingress to the trusted
Front Door path. Set `SECOND_SHIFT_PUBLIC_URL` and the Entra redirect to
the public HTTPS host. Add a rate-limit rule for `/api/v1/external/` using
its host and path, with a separate threshold for the public schema. Size
the rule to accommodate agents that share a NAT address. Set body-size,
header-size, connection and request timeout limits on the edge products
you operate. Preserve the gateway's 256 KiB body limit and timeouts as
a second boundary. Bare requests are refused before the service reads
their bodies. Requests whose signatures need the body use a separate
reader pool until authentication can complete.

Every change made using the break-glass token requires a fresh audit record.
An unavailable audit record blocks the change. Read-only use may be sampled.

## Upgrades, rollback, and cost

- Schedule a maintenance window for each upgrade. Record the current
  revision, image digest and Key Vault versions. Take a PostgreSQL recovery
  point and a consistent Azure Files backup with the writer stopped.
- Use the portal or `az containerapp revision deactivate -g "$rg" -n "$prefix" --revision <old-revision>`
  to deactivate the old revision. Check that it has stopped all replicas
  before deploying the new image. Multiple-revision mode lets you stop the
  old writer before the new one starts. Keep only one active revision.
- Rebuild and push the new release, then rerun the app deployment with the
  new digest and the retained parameters. Check both probes, sign-in, data
  access and audit signing before ending maintenance.
- To roll back, stop the new writer first. Use the prior image and parameters
  if its schema and file formats are compatible. Restore PostgreSQL and files
  to a coordinated point if the release made incompatible data changes.
  Preserve Key Vault key versions and trusted historical signing public keys
  when planning key rotation.
- Budget for the always-running Container App, PostgreSQL compute, storage
  and backups, Azure Files capacity, transactions and snapshots, registry
  storage, Key Vault operations, and Log Analytics ingestion and retention.
  Network egress, availability choices and future agent replicas add costs.

## Monitor the deployment

Deploy the alerts after the app and infrastructure. Use a monitored email
address. In Azure Monitor, test the action group and confirm the email
arrives. Review the rules after changing the service's limits or usage.
[Azure Monitor action groups](https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/action-groups)

```bash
az deployment group create -g "$rg" -n second-shift-monitoring \
  --template-file deploy/azure/monitoring.bicep \
  --parameters prefix="$prefix" operatorEmail='<monitored operator email>'
```

| Alert | When it fires | What to check |
| --- | --- | --- |
| App restarting | The replica's cumulative restart count is above zero. One alert can stay active for the life of that replica. | Check system logs for liveness failures, memory exhaustion, and revision events. [Container Apps metrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-app-containerapps-metrics) |
| App not ready | More than one readiness failure appears in the app's system logs over five minutes. | Check `/readyz`, the latest revision, the database, and the storage mount. [Health probe troubleshooting](https://learn.microsoft.com/en-us/azure/container-apps/troubleshoot-health-probe-failures) |
| Server errors | More than ten HTTP 5xx responses in five minutes. | Find the affected requests in app logs and check whether they coincide with a deployment or a dependency failure. [Container Apps metrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-app-containerapps-metrics) |
| Database CPU high | Average CPU is above 80% for 15 minutes. | Inspect active queries, waits and workload before increasing compute. [PostgreSQL metrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-dbforpostgresql-flexibleservers-metrics) |
| Database storage nearly full | Storage exceeds 80% in the 15-minute window. | Check growth and available capacity. Plan a storage increase if needed. [PostgreSQL metrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-dbforpostgresql-flexibleservers-metrics) |
| Database connections failing | More than five failed connections in five minutes. | Check configuration, credential rotation, private DNS and server connections. [PostgreSQL metrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-dbforpostgresql-flexibleservers-metrics) |
| File share nearly full | The hourly capacity metric is above 80% of the share quota read at deployment, normally 80 GiB of 100 GiB. Rerun the deployment after changing the quota. | Find what is growing and verify backups before removing historical files or increasing the quota. [Azure Files metrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-storage-storageaccounts-fileservices-metrics) |
| Alerts could not be sent | The app logged a delivery failure or no configured alert channel. | Check the delivery page, correct the channel settings and send a test. |
| Saved record unavailable | The app logged a failed saved-record operation. | Check storage access, private PostgreSQL and the logs around the failure. |
| Audit record unavailable | The app logged a failed audit write or could not open the audit file. | Check the data share, signing setup and access. Retry the blocked action once audit writes work again. |

The log rules query this app's [Container Apps logs](https://learn.microsoft.com/en-us/azure/container-apps/log-monitoring)
and send counts. Verify the probe event wording, metrics, scheduled query
evaluation and email delivery in Azure. Bicep compilation checks the
template locally.

## Room for factory agents

Allocate another Container App for each factory-built agent in the same
environment, using a shared runtime image pinned by digest. Give each app a
separate managed identity, resource limits, and only the ingress it needs.
Use separate Key Vault entries for the model provider key and the Brave
Search API key, granting each identity access only to the entries it needs.
Microsoft retired Bing Search APIs on August 11, 2025. Keep the runtime's
settings and outputs separate from the Second Shift data share.

For generated Word, PowerPoint and Excel files, choose a separate Azure
Storage account with container-scoped managed identity access, or a
dedicated SharePoint site. With SharePoint, grant the runtime identity
Microsoft Graph `Sites.Selected` application permission with admin consent
and explicitly grant write access to the selected site. A site grant is
required in addition to the Graph permission. The templates here provision
the Second Shift service. The factory runtime and its document stores are
future deployments.

## Local verification

```bash
for template in vault infra postgres app; do
  az bicep build --file "deploy/azure/$template.bicep" --stdout >/dev/null || break
done
docker build -f deploy/azure/Dockerfile -t second-shift:local .
docker run --rm -d --name second-shift-smoke \
  -e SECOND_SHIFT_DASHBOARD_TOKEN=local-smoke-only \
  -e SECOND_SHIFT_WORLD_BACKEND=sqlite second-shift:local
docker exec second-shift-smoke python -c \
  'from urllib.request import urlopen; print(urlopen("http://127.0.0.1:8000/livez").read().decode())'
docker stop second-shift-smoke
```

Azure CLI Bicep compilation and the Docker/SQLite smoke check ran locally.
No Azure subscription resources were deployed. Entra sign-in, PostgreSQL
private DNS and connectivity, managed identity and Key Vault access, and
Azure Files behavior still require a live subscription check.
