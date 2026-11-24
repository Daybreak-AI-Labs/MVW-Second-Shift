param location string
param serverName string
param subnetId string
param dnsZoneId string
@secure()
param adminPassword string

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: serverName
  location: location
  sku: {
    name: 'Standard_D2ds_v5'
    tier: 'GeneralPurpose'
  }
  properties: {
    administratorLogin: 'secondshiftadmin'
    administratorLoginPassword: adminPassword
    version: '16'
    storage: {
      storageSizeGB: 32
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 14
      geoRedundantBackup: 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: subnetId
      privateDnsZoneArmResourceId: dnsZoneId
      publicNetworkAccess: 'Disabled'
    }
  }
}

output host string = server.properties.fullyQualifiedDomainName
