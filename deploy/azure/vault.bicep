param location string = resourceGroup().location
param vaultName string
@description('Object ID of the deployment operator who manages the initial secrets.')
param operatorObjectId string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    enabledForTemplateDeployment: true
  }
}

resource secretOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, operatorObjectId, 'secrets-officer')
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
    principalId: operatorObjectId
  }
}

resource key 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: 'second-shift-encryption'
  properties: {
    kty: 'RSA'
    keySize: 3072
    keyOps: [
      'wrapKey'
      'unwrapKey'
      'sign'
      'verify'
    ]
  }
}
