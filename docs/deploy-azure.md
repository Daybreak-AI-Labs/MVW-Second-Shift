# Deploy Second Shift to Azure

This kit creates a public HTTPS Container App with Entra sign-in, a private
PostgreSQL Flexible Server, Azure Files, Key Vault, an image registry, and
Log Analytics in one Azure subscription. The service runs with one replica
and uses PostgreSQL row-level security. The app's records (enrolled agents,
trust, drift, platform checks, approvals cards, alerts, sign-in roles) are kept
in PostgreSQL. The settings saved from the Settings page, the signed audit log,
the emergency-stop file, browser sessions and Ekko's stores stay at
`/var/lib/second-shift` on Azure Files. The kit sets a limit of eight connections per database pool
(`SECOND_SHIFT_PG_POOL_SIZE`). See the local load check for total connections
across the app.

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

### Settings fixed by the deployment

The Azure settings overlay shipped in the image fixes these decisions.
The Settings page shows each as **Set by the deployment**.

| Setting | Azure deployment policy |
| --- | --- |
| Separate approver | A different person must approve a waiting request. This applies at every risk level and even when more than one vote is needed. |
| Copilot Studio cannot decide | Refuse the action. |
| Copilot Studio agent is unenrolled | Refuse the action until an administrator enrolls the agent. |
| Older request signatures | Refuse version 1 signatures for all outside agents. Use version 2 when signing requests. |

To change deployment policy, update the overlay in `deploy/azure/service.toml`,
rebuild the image, and deploy the new digest. The Settings page cannot change
or reset a locked value.

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

## Check a deployed revision

After each deployment, run the public checks from a workstation that can
reach the HTTPS origin. Add `--teams-required` if you deployed
the bot. Supply the tenant ID to verify the exact Entra directory.

```bash
deploy/azure/check-deployment.sh "$origin" --tenant-id '<tenant ID>'
```

The check prints a result for each probe and exits with a failure status if
any check fails. It does not follow the sign-in redirect. The gateway check
uses `Expect: 100-continue` and sends only headers. If an ingress sends
`100 Continue` before the rejection or buffers the request, check the same
path at the app ingress to see where the early refusal was lost.

To also exercise agent enrollment and key handling, supply the name of a
vault secret that contains a short-lived administrator credential. Use a
delegated Entra access token with the Second Shift audience and admin role,
or pass `--admin-session` if the secret is the signed-in administrator's
`ss_session` cookie value. The test needs an attributable administrator for
credential minting. The break-glass token does not establish that identity.
[Read a secret with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/keyvault/secret#az-keyvault-secret-show)

```bash
deploy/azure/check-deployment.sh "$origin" --vault "$vault" \
  --admin-secret '<short-lived admin credential secret name>'
```

The optional check screens a low-risk proposal without running it, tries one
wrong key and removes the temporary enrollment. If the deployment requires
a human decision before minting a key, the script reports that and removes
the enrollment. Leave the approval rule enabled. If cleanup fails, use the
printed agent ID to find the enrollment. The script never prints credentials
or raw responses. Remove the short-lived vault credential when finished.

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

## Local load check

From a Linux checkout with Python 3.12 and the PostgreSQL extra installed,
point the developer tool at a disposable PostgreSQL 16 service. It requires
an explicit `127.0.0.1` bootstrap login that can create roles and databases.
It launches one local app process, creates a fresh database and a
non-superuser service login for the run, and removes both on exit.

```bash
docker run --rm -d --name second-shift-load-db -p 127.0.0.1:55432:5432 \
  -e POSTGRES_PASSWORD=local-load-only postgres:16
export SECOND_SHIFT_LOAD_DSN='postgresql://postgres:local-load-only@127.0.0.1:55432/postgres'
.venv/bin/python -m tools.load_check --people 50 --agents 25
docker stop second-shift-load-db
unset SECOND_SHIFT_LOAD_DSN
```

Each person opens Home, Outside agents and Approvals once in sequence using
a registered, signed-in session. Each enrolled agent screens one low-risk
proposal and reports one run with its own key. The concurrent burst also
includes ten card rejections through the Teams webhook. The tool signs
those activities with a local test key and uses a stand-in for the outbound
Teams connector. It checks that the returned card records the rejection.
The runs use row-level security, encrypted records, an explicit workspace
(`SECOND_SHIFT_CLIENT_ID`), a deployment key with its expected digest
(`SECOND_SHIFT_ENCRYPTION_KEY_DIGEST`), and the kit's pool setting of eight.
The tool measures complete HTTP responses on loopback. The test excludes
sign-in redirects, browser asset downloads and network time to Microsoft or
Azure, and uses local files for state held on Azure Files in the kit.

The benchmark used Python 3.12.14 on Linux 6.18.57 on an AMD EPYC 9V74
host. The container had a four-CPU quota and 16 GiB of memory. PostgreSQL
16.16 ran in a separate local container with a 100-connection limit.
One test run was made for each combination. Counts are the number of
clients that started together. Timings include queueing and all attempts,
including refusals. They describe a local burst with synthetic data.

End-to-end response times are median / 95th percentile in seconds.

| People | Agents | Home | Outside agents | Approvals | Screen | Report run | Teams card | Failed requests |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | 25 | 7.64 / 7.71 | 5.32 / 5.71 | 2.20 / 2.45 | 7.62 / 7.68 | 5.70 / 8.45 | 7.64 / 7.66 | 0 |
| 50 | 100 | 9.60 / 9.66 | 8.13 / 9.28 | 2.92 / 3.35 | 3.76 / 10.30 | 9.10 / 13.10 | 9.63 / 9.64 | 112 |
| 200 | 25 | 26.39 / 27.02 | 15.87 / 26.38 | 9.53 / 11.11 | 14.95 / 26.56 | 16.90 / 20.76 | 26.96 / 26.99 | 0 |
| 200 | 100 | 31.31 / 31.82 | 18.17 / 37.18 | 6.67 / 9.75 | 3.03 / 7.77 | 29.79 / 34.26 | 31.80 / 31.84 | 135 |
| 1,000 | 25 | 81.10 / 134.47 | 102.47 / 139.35 | 41.90 / 49.50 | 63.52 / 69.73 | 84.42 / 86.67 | 134.53 / 134.53 | 0 |
| 1,000 | 100 | 86.79 / 152.44 | 123.16 / 164.41 | 41.95 / 50.19 | 9.51 / 63.44 | 51.61 / 114.11 | 152.50 / 152.51 | 136 |

PostgreSQL connections were sampled about every 100 ms. App CPU is the
average number of logical CPU cores used by the app process during the burst.

| People | Agents | Burst seconds | App CPU cores | Peak open | Peak non-idle | Peak waiting for a database lock |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | 25 | 15.48 | 0.95 | 30 | 13 | 0 |
| 50 | 100 | 21.04 | 0.91 | 38 | 13 | 0 |
| 200 | 25 | 51.90 | 1.03 | 37 | 14 | 0 |
| 200 | 100 | 59.26 | 1.03 | 30 | 15 | 0 |
| 1,000 | 25 | 241.70 | 1.07 | 36 | 16 | 0 |
| 1,000 | 100 | 269.19 | 1.07 | 38 | 15 | 0 |

**What limits the app first.** Page latency grew as the one app process
used roughly one full CPU core. At 1,000 people, the home page took over
two minutes at the 95th percentile. All page and Teams requests completed,
and all agent calls in the 25-agent runs completed. In the 100-agent
bursts, the agent gateway returned 503 responses for 56 to 68 screening
requests and 56 to 68 run reports per run. The gateway admits up to 32
authenticated requests concurrently and returns a busy response when a slot
does not open within one second. It rejected traffic before PostgreSQL
reached its connection limit.

Peak open connections stayed at or below 38 of the server's 100. The
configured limit of eight applies to each pool. Connection sampling saw
no waits for PostgreSQL heavyweight locks. It does not measure short waits
between samples, per-pool checkout queues, or application locks. The
local results establish the behavior of these six single-process bursts.
The Azure kit's CPU allocation, storage and network require a separate
measurement in the intended deployment.

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
