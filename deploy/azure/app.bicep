param location string = resourceGroup().location
@minValue(1)
@maxValue(8)
@description('Dashboard processes in the single Second Shift replica.')
param dashboardWorkers int = 6
param prefix string
param vaultName string
param entraClientId string
@description('Registry-relative image pinned by digest, such as second-shift@sha256:...')
param image string
@description('Optional Second Shift environment variables with non-secret platform-check settings.')
param platformSettings object = {}
@description('Optional map of platform-check environment names to vault secret names.')
param platformVaultReferences object = {}
@description('Optional map of vault secret names to immutable Key Vault versions.')
param secretVersions object = {}
@description('Create a single-tenant Azure Bot and enable the Microsoft Teams channel.')
param enableTeams bool = false
@description('Application (client) ID of the single-tenant Teams bot registration when Teams is enabled.')
param teamsBotAppId string = ''

var suffix = uniqueString(resourceGroup().id, prefix)
var dataPath = '/var/lib/second-shift'
var tenantId = subscription().tenantId
var entraOrigin = uri(environment().authentication.loginEndpoint, tenantId)
var issuer = '${entraOrigin}/v2.0'
var loginBase = '${entraOrigin}/oauth2/v2.0'
var publicOrigin = 'https://${prefix}.${appsEnvironment.properties.defaultDomain}'
var vaultUri = vault.properties.vaultUri
var storageName = 'second-shift-data'
var teamsVaultReferences = enableTeams ? { SECOND_SHIFT_TEAMS_BOT_SECRET: 'teams-bot-secret' } : {}
var references = union(platformVaultReferences, teamsVaultReferences, {
  SECOND_SHIFT_PG_DSN: 'postgres-dsn'
  SECOND_SHIFT_OIDC_CLIENT_SECRET: 'oidc-client-secret'
  SECOND_SHIFT_OIDC_SESSION_SECRET: 'oidc-session-secret'
  SECOND_SHIFT_DASHBOARD_TOKEN: 'dashboard-token'
  SECOND_SHIFT_ENCRYPTION_KEY: 'deployment-encryption-key'
  SECOND_SHIFT_AUDIT_SIGNING_KEY: 'audit-signing-key'
})
var secretNames = union(map(items(references), reference => reference.value), [])

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}

resource envSecrets 'Microsoft.KeyVault/vaults/secrets@2023-07-01' existing = [
  for name in secretNames: {
    parent: vault
    name: name
  }
]

resource secretAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (name, i) in secretNames: {
    scope: envSecrets[i]
    name: guid(envSecrets[i].id, identity.id, 'read')
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
      principalId: identity.properties.principalId
      principalType: 'ServicePrincipal'
    }
  }
]

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: '${prefix}-service'
}

resource appsEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: '${prefix}-apps'
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: 'ssregistry${suffix}'
}

var settings = union(platformSettings, {
  SECOND_SHIFT_HOME: dataPath
  SECOND_SHIFT_CONFIG_OVERLAY: '/opt/second-shift/service.toml'
  SECOND_SHIFT_PUBLIC_URL: publicOrigin
  SECOND_SHIFT_DASHBOARD_REQUIRE_AUTH: '1'
  SECOND_SHIFT_OIDC_ENABLED: '1'
  SECOND_SHIFT_OIDC_CLIENT_ID: entraClientId
  SECOND_SHIFT_OIDC_ISSUER: issuer
  SECOND_SHIFT_OIDC_AUDIENCE: entraClientId
  SECOND_SHIFT_OIDC_ALGORITHMS: 'RS256'
  SECOND_SHIFT_OIDC_JWKS_URI: '${entraOrigin}/discovery/v2.0/keys'
  SECOND_SHIFT_OIDC_AUTHORIZATION_ENDPOINT: '${loginBase}/authorize'
  SECOND_SHIFT_OIDC_TOKEN_ENDPOINT: '${loginBase}/token'
  SECOND_SHIFT_OIDC_END_SESSION_ENDPOINT: '${loginBase}/logout'
  SECOND_SHIFT_OIDC_REDIRECT_URI: '${publicOrigin}/auth/callback'
  SECOND_SHIFT_ENCRYPT_AT_REST: '1'
  SECOND_SHIFT_ENCRYPT_STRICT: '1'
  SECOND_SHIFT_ENCRYPT_PER_TENANT: '1'
  SECOND_SHIFT_KMS_KEY_ID: '${vaultUri}keys/second-shift-encryption'
  SECOND_SHIFT_AUDIT_REQUIRE_OFFHOST_KEY: '1'
  SECOND_SHIFT_WORLD_BACKEND: 'postgres'
  SECOND_SHIFT_PG_POOL_SIZE: '6'
  SECOND_SHIFT_DASHBOARD_WORKERS: string(dashboardWorkers)
  SECOND_SHIFT_PG_RLS: '1'
  SECOND_SHIFT_EXTERNAL_AGENTS: '1'
  AZURE_CLIENT_ID: identity.properties.clientId
})

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: prefix
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    managedEnvironmentId: appsEnvironment.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Multiple'
      ingress: {
        external: true
        targetPort: 8000
        transport: 'http'
        allowInsecure: false
        traffic: [{ latestRevision: true, weight: 100 }]
      }
      registries: [
        { server: registry.properties.loginServer, identity: identity.id }
      ]
      secrets: [
        for name in secretNames: {
          name: 's-${uniqueString(name)}'
          keyVaultUrl: '${vaultUri}secrets/${name}${contains(secretVersions, name) ? '/${secretVersions[name]}' : ''}'
          identity: identity.id
        }
      ]
    }
    template: {
      scale: { minReplicas: 1, maxReplicas: 1 }
      volumes: [
        {
          name: 'data'
          storageName: storageName
          storageType: 'AzureFile'
          mountOptions: 'uid=10001,gid=10001,dir_mode=0700,file_mode=0600'
        }
      ]
      containers: [
        {
          name: 'second-shift'
          image: '${registry.properties.loginServer}/${image}'
          // https://learn.microsoft.com/en-us/azure/container-apps/containers#allocations
          resources: { cpu: json('4.0'), memory: '8Gi' }
          volumeMounts: [
            { volumeName: 'data', mountPath: dataPath }
          ]
          env: concat(
            map(items(settings), setting => { name: setting.key, value: setting.value }),
            map(items(references), reference => { name: reference.key, secretRef: 's-${uniqueString(reference.value)}' })
          )
          probes: [
            {
              type: 'Startup'
              httpGet: { path: '/livez', port: 8000 }
              periodSeconds: 5
              timeoutSeconds: 3
              failureThreshold: 30
            }
            {
              type: 'Liveness'
              httpGet: { path: '/livez', port: 8000 }
              periodSeconds: 15
              timeoutSeconds: 3
            }
            {
              type: 'Readiness'
              httpGet: { path: '/readyz', port: 8000 }
              periodSeconds: 10
              timeoutSeconds: 5
            }
          ]
        }
      ]
    }
  }
  dependsOn: [secretAccess]
}

module teams 'teams.bicep' = if (enableTeams) {
  name: 'second-shift-teams-bot'
  params: {
    botName: '${prefix}-teams-${suffix}'
    botAppId: teamsBotAppId
    tenantId: tenantId
    publicOrigin: publicOrigin
  }
}

output publicOrigin string = 'https://${app.properties.configuration.ingress.fqdn}'
