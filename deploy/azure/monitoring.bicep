param location string = resourceGroup().location
param prefix string
@description('Email address that receives Azure monitoring alerts for Second Shift.')
@minLength(3)
param operatorEmail string

var suffix = uniqueString(resourceGroup().id, prefix)

// These references match the resources created by app.bicep and infra.bicep.
// https://learn.microsoft.com/en-us/azure/templates/microsoft.app/2024-03-01/containerapps
resource app 'Microsoft.App/containerApps@2024-03-01' existing = {
  name: prefix
}
// https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/2024-08-01/flexibleservers
resource database 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' existing = {
  name: '${prefix}-${suffix}'
}
// https://learn.microsoft.com/en-us/azure/templates/microsoft.operationalinsights/2023-09-01/workspaces
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: '${prefix}-logs'
}
// https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/2023-05-01/storageaccounts/fileservices/shares
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: 'ss${suffix}' }
resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' existing = {
  parent: storage
  name: 'default'
}
resource share 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' existing = {
  parent: fileService
  name: 'second-shift-data'
}

// https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/2023-01-01/actiongroups
resource operators 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${prefix}-operators'
  location: 'global'
  properties: {
    enabled: true
    groupShortName: 'SecondShift'
    emailReceivers: [{ name: 'Second Shift operator', emailAddress: operatorEmail, useCommonAlertSchema: true }]
  }
}

var noDimensions = []
var metricRules = [
  // https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-app-containerapps-metrics
  {
    key: 'app-restarting'
    description: 'Second Shift has restarted. Review container system logs and check readiness.'
    scope: app.id
    metricNamespace: 'Microsoft.App/containerApps'
    metric: 'RestartCount'
    aggregation: 'Maximum'
    threshold: 0
    window: 'PT5M'
    frequency: 'PT1M'
    dimensions: noDimensions
  }
  {
    key: 'app-server-errors'
    description: 'Second Shift returned more than ten server errors in five minutes. Review the app and database logs.'
    scope: app.id
    metricNamespace: 'Microsoft.App/containerApps'
    metric: 'Requests'
    aggregation: 'Total'
    threshold: 10
    window: 'PT5M'
    frequency: 'PT1M'
    dimensions: [{ name: 'statusCodeCategory', operator: 'Include', values: ['5xx'] }]
  }
  // https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-dbforpostgresql-flexibleservers-metrics
  {
    key: 'database-cpu-high'
    description: 'PostgreSQL CPU is above 80% on average. Inspect active queries before increasing compute.'
    scope: database.id
    metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
    metric: 'cpu_percent'
    aggregation: 'Average'
    threshold: 80
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: noDimensions
  }
  {
    key: 'database-storage-nearly-full'
    description: 'PostgreSQL storage is above 80%. Check storage growth and available capacity.'
    scope: database.id
    metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
    metric: 'storage_percent'
    aggregation: 'Maximum'
    threshold: 80
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: noDimensions
  }
  {
    key: 'database-connections-failing'
    description: 'More than five PostgreSQL connection attempts failed in five minutes. Check credentials, DNS and server capacity.'
    scope: database.id
    metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
    metric: 'connections_failed'
    aggregation: 'Total'
    threshold: 5
    window: 'PT5M'
    frequency: 'PT1M'
    dimensions: noDimensions
  }
  // The kit uses a standard SMB share. Use capacity in bytes and a threshold
  // based on the share quota, not the percentage metric for provisioned shares.
  // https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-storage-storageaccounts-fileservices-metrics
  // https://learn.microsoft.com/en-us/azure/storage/files/files-monitoring-alerts
  {
    key: 'file-share-nearly-full'
    description: 'Azure Files is above 80% of its quota. Review file growth, backups and free space.'
    scope: fileService.id
    metricNamespace: 'Microsoft.Storage/storageAccounts/fileServices'
    metric: 'FileCapacity'
    aggregation: 'Average'
    threshold: 0
    window: 'PT1H'
    frequency: 'PT15M'
    dimensions: [{ name: 'FileShare', operator: 'Include', values: [share.name] }]
  }
]

// https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/metricalerts
resource metrics 'Microsoft.Insights/metricAlerts@2018-03-01' = [
  for rule in metricRules: {
    name: '${prefix}-${rule.key}'
    location: 'global'
    properties: {
      description: rule.description
      scopes: [rule.scope]
      severity: 2
      enabled: true
      autoMitigate: true
      windowSize: rule.window
      evaluationFrequency: rule.frequency
      actions: [{ actionGroupId: operators.id }]
      criteria: {
        'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
        allOf: [{
          name: rule.key
          criterionType: 'StaticThresholdCriterion'
          metricName: rule.metric
          metricNamespace: rule.metricNamespace
          timeAggregation: rule.aggregation
          dimensions: rule.dimensions
          operator: 'GreaterThan'
          threshold: rule.metric == 'FileCapacity' ? ((share.properties.shareQuota ?? 100) * 1073741824 * 80 / 100) : rule.threshold
        }]
      }
    }
  }
]

// https://learn.microsoft.com/en-us/azure/container-apps/log-monitoring
// https://learn.microsoft.com/en-us/azure/container-apps/troubleshoot-deployment-errors#find-system-level-failures
var systemLogs = 'ContainerAppSystemLogs_CL | where ContainerAppName_s == "${prefix}"'
var appLogs = 'ContainerAppConsoleLogs_CL | where ContainerAppName_s == "${prefix}"'
var logRules = [
  {
    key: 'app-not-ready'
    title: 'Second Shift is not ready'
    description: 'Second Shift failed repeated readiness checks. Check the ready endpoint and the latest revision logs.'
    query: '${systemLogs} | where Log_s has "readiness" and (Log_s has "failed" or Reason_s == "Unhealthy")'
    threshold: 1
  }
  {
    key: 'alerts-could-not-be-sent'
    title: 'Second Shift alerts could not be sent'
    description: 'Second Shift could not deliver an operational alert. Check the alert status page and send a test.'
    query: '${appLogs} | where Log_s contains "ops alert delivery failed" or Log_s contains "no alert channel" or Log_s contains "notify email failed" or Log_s contains "notify teams failed" or Log_s contains "notify dispatch unavailable"'
    threshold: 0
  }
  {
    key: 'saved-record-unavailable'
    title: 'A saved record is unavailable'
    description: 'Second Shift could not read or write a saved record. Check the database and the deployment storage.'
    query: '${appLogs} | where Log_s contains "saved record unavailable"'
    threshold: 0
  }
  {
    key: 'audit-record-unavailable'
    title: 'An audit record is unavailable'
    description: 'Second Shift could not write a required audit record. Check storage, the signing key and the app logs.'
    query: '${appLogs} | where Log_s contains "audit: live file is unavailable" or Log_s contains "audit: strict signed write" or Log_s contains "audit: write failed" or Log_s contains "audit write failed" or Log_s contains "audit signer: write failed"'
    threshold: 0
  }
]

// https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/2023-12-01/scheduledqueryrules
resource logs 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = [
  for rule in logRules: {
    name: '${prefix}-${rule.key}'
    location: location
    kind: 'LogAlert'
    properties: {
      displayName: rule.title
      description: rule.description
      enabled: true
      severity: 2
      scopes: [workspace.id]
      evaluationFrequency: 'PT5M'
      windowSize: 'PT5M'
      // Container Apps creates these tables after the first log arrives.
      skipQueryValidation: true
      autoMitigate: true
      criteria: {
        allOf: [{
          query: rule.query
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: rule.threshold
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }]
      }
      actions: { actionGroups: [operators.id] }
    }
  }
]
