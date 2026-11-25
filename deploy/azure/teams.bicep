param botName string
@minLength(36)
@maxLength(36)
@description('Application (client) ID of the single-tenant Entra registration for the Teams bot.')
param botAppId string
param tenantId string
param publicOrigin string

// https://learn.microsoft.com/en-us/azure/templates/microsoft.botservice/2022-09-15/botservices
// https://learn.microsoft.com/en-us/microsoftteams/platform/teams-sdk/teams/app-authentication/client-secret
resource bot 'Microsoft.BotService/botServices@2022-09-15' = {
  name: botName
  location: 'global'
  kind: 'azurebot'
  sku: { name: 'F0' }
  properties: {
    displayName: 'Second Shift Approvals'
    endpoint: '${publicOrigin}/webhook/teams'
    msaAppId: botAppId
    msaAppType: 'SingleTenant'
    msaAppTenantId: tenantId
  }
}

// https://learn.microsoft.com/en-us/azure/templates/microsoft.botservice/2022-09-15/botservices/channels
resource teamsChannel 'Microsoft.BotService/botServices/channels@2022-09-15' = {
  parent: bot
  name: 'MsTeamsChannel'
  location: 'global'
  properties: {
    channelName: 'MsTeamsChannel'
    properties: { isEnabled: true }
  }
}
