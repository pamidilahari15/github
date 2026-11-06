<#
.SYNOPSIS
    One-time permission setup for the SOAR-001 playbook (Reset-Entra-ID Password).

.DESCRIPTION
    Grants what cannot be deployed through the Sentinel repository workflow:
      1. Microsoft Graph application permissions on the playbook's managed identity
      2. The "User Administrator" Entra directory role on that identity
      3. Microsoft Sentinel Responder on the workspace for the playbook identity
      4. Microsoft Sentinel Automation Contributor on the resource group for the
         Microsoft Sentinel service principal, so automation rules can run the playbook

    Run it after the playbook is deployed and BEFORE the automation rule is deployed.
    Requires Azure CLI.
      - Azure steps (3, 4) need Owner / User Access Administrator on the resource group.
      - Entra steps (1, 2) need Privileged Role Administrator or Global Administrator.
    If one account cannot do both, run the script twice with -SkipEntra and -SkipAzure.

    Mail.Send is tenant-wide by default. Restrict it to the sender mailbox with an
    Exchange Online application access policy or RBAC for Applications.
#>
[CmdletBinding()]
param(
    [string]$ResourceGroupName = 'sentinel-github',
    [string]$WorkspaceName     = 'github',
    [string]$PlaybookName      = 'SOAR-001-Reset-Entra-ID-Password',
    [switch]$SkipEntra,
    [switch]$SkipAzure
)

$ErrorActionPreference = 'Stop'

$graphAppId           = '00000003-0000-0000-c000-000000000000'
$sentinelAppId        = '98785600-1bb7-4fb9-b9fa-19afe2c8a360'  # Azure Security Insights
$userAdminTemplateId  = 'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
$graphPermissions     = @(
    'User-PasswordProfile.ReadWrite.All',
    'User.RevokeSessions.All',
    'Directory.Read.All',
    'Mail.Send'
)

function Invoke-GraphRest {
    # az is a .cmd file on Windows: keep ( ) & out of arguments and pass query options separately.
    param([string]$Method, [string]$Url, $Body, [string[]]$QueryParameters)
    $ErrorActionPreference = 'Continue'
    $arguments = @('rest', '--method', $Method, '--url', $Url, '--headers', 'Content-Type=application/json')
    if ($QueryParameters) { $arguments += @('--url-parameters') + $QueryParameters }
    if ($null -ne $Body) {
        $tmp = New-TemporaryFile
        try {
            ($Body | ConvertTo-Json -Depth 10) | Set-Content -Path $tmp -Encoding utf8
            $arguments += @('--body', "@$tmp")
            $output = & az @arguments 2>&1
        }
        finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    else {
        $output = & az @arguments 2>&1
    }
    if ($LASTEXITCODE -ne 0) { throw ($output | Out-String) }
    if ($output) { return ($output | Out-String | ConvertFrom-Json) }
}

$subscriptionId = az account show --query id -o tsv
Write-Host "Subscription: $subscriptionId"

$principalId = az resource show -g $ResourceGroupName -n $PlaybookName `
    --resource-type Microsoft.Logic/workflows --query identity.principalId -o tsv
if (-not $principalId) { throw "Playbook '$PlaybookName' not found or has no managed identity. Deploy it first." }
Write-Host "Playbook managed identity: $principalId"

# 1. Microsoft Graph application permissions
if ($SkipEntra) { Write-Host 'Skipping Entra steps (Graph permissions, directory role).' }
else {
$graphSp = (Invoke-GraphRest GET 'https://graph.microsoft.com/v1.0/servicePrincipals' -QueryParameters "`$filter=appId eq '$graphAppId'", '$select=id,appRoles').value | Select-Object -First 1
if (-not $graphSp) { throw 'Microsoft Graph service principal not found.' }
$existing = (Invoke-GraphRest GET "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments").value
foreach ($permission in $graphPermissions) {
    $role = $graphSp.appRoles | Where-Object { $_.value -eq $permission -and $_.allowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Graph application permission '$permission' not found." }
    if ($existing | Where-Object { $_.appRoleId -eq $role.id }) {
        Write-Host "Graph permission already granted: $permission"
        continue
    }
    Invoke-GraphRest POST "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" @{
        principalId = $principalId
        resourceId  = $graphSp.id
        appRoleId   = $role.id
    } | Out-Null
    Write-Host "Granted Graph permission: $permission"
}

# 2. User Administrator directory role
$roleAssignments = (Invoke-GraphRest GET 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -QueryParameters "`$filter=principalId eq '$principalId'").value
if ($roleAssignments | Where-Object { $_.roleDefinitionId -eq $userAdminTemplateId }) {
    Write-Host 'User Administrator role already assigned.'
}
else {
    Invoke-GraphRest POST 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' @{
        principalId      = $principalId
        roleDefinitionId = $userAdminTemplateId
        directoryScopeId = '/'
    } | Out-Null
    Write-Host 'Assigned directory role: User Administrator'
}
}

# 3. Sentinel Responder for the playbook identity on the workspace
if ($SkipAzure) { Write-Host 'Skipping Azure RBAC steps.' }
else {
$workspaceScope = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
    --role 'Microsoft Sentinel Responder' --scope $workspaceScope --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to assign Microsoft Sentinel Responder.' }
Write-Host 'Ensured Microsoft Sentinel Responder on the workspace.'

# 4. Sentinel Automation Contributor for the Microsoft Sentinel service principal on the resource group
$rgScope = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName"
az role assignment create --assignee $sentinelAppId --role 'Microsoft Sentinel Automation Contributor' `
    --scope $rgScope --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to assign Microsoft Sentinel Automation Contributor.' }
Write-Host 'Ensured Microsoft Sentinel Automation Contributor on the resource group.'
}

Write-Host 'Done.'
