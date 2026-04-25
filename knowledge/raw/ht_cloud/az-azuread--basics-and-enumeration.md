# Az - Entra ID (AzureAD) & Azure IAM

## Basic Information

Azure Active Directory (Azure AD) serves as Microsoft's cloud-based service for identity and access management. It is instrumental in enabling employees to sign in and gain access to resources, both within and beyond the organization, encompassing Microsoft 365, the Azure portal, and a multitude of other SaaS applications. The design of Azure AD focuses on delivering essential identity services, prominently including **authentication, authorization, and user management**.

Key features of Azure AD involve **multi-factor authentication** and **conditional access**, alongside seamless integration with other Microsoft security services. These features significantly elevate the security of user identities and empower organizations to effectively implement and enforce their access policies. As a fundamental component of Microsoft's cloud services ecosystem, Azure AD is pivotal for the cloud-based management of user identities.

## Enumeration

### **Connection**

{{#tabs }}
{{#tab name="az cli" }}

```bash
az login #This will open the browser (if not use --use-device-code)
az login -u <username> -p <password> #Specify user and password
az login --identity #Use the current machine managed identity (metadata)
az login --identity -u /subscriptions/<subscriptionId>/resourcegroups/myRG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myID #Login with user managed identity

# Login as service principal
## With password
az login --service-principal -u <application ID> -p VerySecret --tenant contoso.onmicrosoft.com # Tenant can also be the tenant UUID
## With cert
az login --service-principal -u <application ID> -p ~/mycertfile.pem --tenant contoso.onmicrosoft.com

# Request access token (ARM)
az account get-access-token
# Request access token for different resource. Supported tokens: aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms
az account get-access-token --resource-type aad-graph

# If you want to configure some defaults
az configure

# Get user logged-in already
az ad signed-in-user show

# Help
az find "vm" # Find vm commands
az vm -h # Get subdomains
az ad user list --query-examples # Get examples
```

{{#endtab }}

{{#tab name="Mg" }}

```bash
# Login Open browser
Connect-MgGraph

# Login with service principal secret
## App ID and Tenant ID of your Azure AD App Registration
$appId = "<appId>"
$tenantId = "<tenantId>"
$clientSecret = "<clientSecret>"
## Convert the client secret to a SecureString
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
## Create a PSCredential object
$credential = New-Object System.Management.Automation.PSCredential ($appId, $secureSecret)
## Connect using client credentials
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Login with token
$token = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
$secureToken = ConvertTo-SecureString $token -AsPlainText -Force
Connect-MgGraph -AccessToken $secureToken

# Get token from session
Parameters = @{
    Method     = "GET"
    Uri        = "/v1.0/me"
    OutputType = "HttpResponseMessage"
}
$Response = Invoke-MgGraphRequest @Parameters
$Headers = $Response.RequestMessage.Headers
$Headers.Authorization.Parameter

# Find commands
Find-MgGraphCommand -command *Mg*
```

{{#endtab }}

{{#tab name="Az" }}

```bash
Connect-AzAccount #Open browser
# Using credentials
$passwd = ConvertTo-SecureString "Welcome2022!" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@corp.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds

# Get Access Token
# Request access token to other endpoints: AadGraph, AnalysisServices, Arm, Attestation, Batch, DataLake, KeyVault, MSGraph, OperationalInsights, ResourceManager, Storage, Synapse
(ConvertFrom-SecureString (Get-AzAccessToken -ResourceTypeName Arm -AsSecureString).Token -AsPlainText)

# Connect with access token
Connect-AzAccount -AccountId test@corp.onmicrosoft.com [-AccessToken $ManagementToken] [-GraphAccessToken $AADGraphToken] [-MicrosoftGraphAccessToken $MicrosoftGraphToken] [-KeyVaultAccessToken $KeyVaultToken]
# If connecting with some metadata token, in "-AccountId" put the OID of the managed identity (get it from the JWT token)

# Connect with Service principal/enterprise app secret
$password = ConvertTo-SecureString 'KWEFNOIRFIPMWL.--DWPNVFI._EDWWEF_ADF~SODNFBWRBIF' -AsPlainText -Force
$creds = New-Object
 System.Management.Automation.PSCredential('2923847f-fca2-a420-df10-a01928bec653', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 29sd87e56-a192-a934-bca3-0398471ab4e7d

#All the Azure AD cmdlets have the format *-AzAD*
Get-Command *azad*
#Cmdlets for other Azure resources have the format *Az*
Get-Command *az*
```

{{#endtab }}

{{#tab name="Raw PS" }}

```bash
#Using management
$Token = 'eyJ0eXAi..'
# List subscriptions
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
  Method  = 'GET'
  Uri     = $URI
  Headers = @{
      'Authorization' = "Bearer $Token"
  }
}
(Invoke-RestMethod @RequestParams).value

# Using graph
Invoke-WebRequest -Uri "https://graph.windows.net/myorganization/users?api-version=1.6" -Headers @{Authorization="Bearer {0}" -f $Token}
```

{{#endtab }}

{{#tab name="curl" }}

```bash
# Request tokens to access endpoints
# ARM
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER

# Vault
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

{{#endtab }}
{{#tab name="MS Graph" }}

```bash
Get-MgTenantRelationshipDelegatedAdminCustomer
# Install the Microsoft Graph PowerShell module if not already installed
Install-Module Microsoft.Graph -Scope CurrentUser

# Import the module
Import-Module Microsoft.Graph

# Login to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Directory.Read.All"

# Enumerate available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph*

# Example: List users
Get-MgUser -All

# Example: List groups
Get-MgGroup -All

# Example: Get roles assigned to a user
Get-MgUserAppRoleAssignment -UserId <UserId>

# Disconnect from Microsoft Graph
Disconnect-MgGraph
```
{{#endtab }}

{{#tab name="Azure AD" }}

```bash
Connect-AzureAD #Open browser
# Using credentials
$passwd = ConvertTo-SecureString "Welcome2022!" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@corp.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds

# Using tokens
## AzureAD cannot request tokens, but can use AADGraph and MSGraph tokens to connect
Connect-AzureAD -AccountId test@corp.onmicrosoft.com -AadAccessToken $token
```

{{#endtab }}
{{#endtabs }}

When you **login** via **CLI** into Azure with any program, you are using an **Azure Application** from a **tenant** that belongs to **Microsoft**. These Applications, like the ones you can create in your account, **have a client id**. You **won't be able to see all of them** in the **allowed applications lists** you can see in the console, **but they are allowed by default**.

For example a **powershell script** that **authenticates** use an app with client id **`1950a258-227b-4e31-a9cf-717495945fc2`**. Even if the app doesn't appear in the console, a sysadmin could **block that application** so users cannot access using tools that connects via that App.

However, there are **other client-ids** of applications that **will allow you to connect to Azure**:

```bash
# The important part is the ClientId, which identifies the application to login inside Azure

$token = Invoke-Authorize -Credential $credential `
                         -ClientId '1dfb5f98-f363-4b0f-b63a-8d20ada1e62d' `
                         -Scope 'Files.Read.All openid profile Sites.Read.All User.Read email' `
                         -Redirect_Uri "https://graphtryit-staging.azurewebsites.net/" `
                         -Verbose -Debug `
                         -InformationAction Continue

$token = Invoke-Authorize -Credential $credential `
                         -ClientId '65611c08-af8c-46fc-ad20-1888eb1b70d9' `
                         -Scope 'openid profile Sites.Read.All User.Read email' `
                         -Redirect_Uri "chrome-extension://imjekgehfljppdblckcmjggcoboemlah" `
                         -Verbose -Debug `
                         -InformationAction Continue

$token = Invoke-Authorize -Credential $credential `
                         -ClientId 'd3ce4cf8-6810-442d-b42e-375e14710095' `
                         -Scope 'openid' `
                         -Redirect_Uri "https://graphexplorer.azurewebsites.net/" `
                         -Verbose -Debug `
                         -InformationAction Continue
```

### Tenants

{{#tabs }}
{{#tab name="az cli" }}

```bash
# List tenants
az account tenant list
```

{{#endtab }}
{{#endtabs }}

### Users

For more information about Entra ID users check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# Enumerate users
az ad user list --output table
az ad user list --query "[].userPrincipalName"
# Get info of 1 user
az ad user show --id "test@corp.onmicrosoft.com"
# Search "admin" users
az ad user list --query "[].displayName" | findstr /i "admin"
az ad user list --query "[?contains(displayName,'admin')].displayName"
# Search attributes containing the word "password"
az ad user list | findstr /i "password" | findstr /v "null,"
# All users from Entra ID
az ad user list --query "[].{osi:onPremisesSecurityIdentifier,upn:userPrincipalName}[?osi==null]"
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
# All users synced from on-prem
az ad user list --query "[].{osi:onPremisesSecurityIdentifier,upn:userPrincipalName}[?osi!=null]"
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"
# Get groups where the user is a member
az ad user get-member-groups --id <email>
# Get roles assigned to the user in Azure (NOT in Entra ID)
az role assignment list --include-inherited --include-groups --include-classic-administrators true --assignee <email>
# Get ALL roles assigned in Azure in the current subscription (NOT in Entra ID)
az role assignment list --include-inherited --include-groups --include-classic-administrators true --all

# Get EntraID roles assigned to a user
## Get Token
export TOKEN=$(az account get-access-token --resource https://graph.microsoft.com/ --query accessToken -o tsv)
## Get users
curl -X GET "https://graph.microsoft.com/v1.0/users" \
    -H "Authorization: Bearer $TOKEN" \ -H "Content-Type: application/json" | jq
## Get EntraID roles assigned to an user
curl -X GET "https://graph.microsoft.com/beta/rolemanagement/directory/transitiveRoleAssignments?\$count=true&\$filter=principalId%20eq%20'86b10631-ff01-4e73-a031-29e505565caa'" \
-H "Authorization: Bearer $TOKEN" \
-H "ConsistencyLevel: eventual" \
-H "Content-Type: application/json" | jq
## Get role details
curl -X GET "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/cf1c38e5-3621-4004-a7cb-879624dced7c" \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" | jq
```

{{#endtab }}

{{#tab name="MS Graph" }}

```bash
# Enumerate users using Microsoft Graph PowerShell
Get-MgUser -All

# Get user details
Get-MgUser -UserId "test@corp.onmicrosoft.com" | Format-List *

# Search "admin" users
Get-MgUser -All | Where-Object { $_.DisplayName -like "*test*" } | Select-Object DisplayName

# Search attributes containing the word "password"
Get-MgUser -All | Where-Object { $_.AdditionalProperties.PSObject.Properties.Name -contains "password" }

# All users from Entra ID
Get-MgUser -Filter "startswith(userPrincipalName, 't')" -All | Select-Object DisplayName, UserPrincipalName

# Get groups where the user is a member
Get-MgUserMemberOf -UserId <UserId>

# Get roles assigned to the user in Entra ID
Get-MgUserAppRoleAssignment -UserId <UserId>

# List available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph.Users
```
{{#endtab }}

{{#tab name="Azure AD" }}

```bash
# Enumerate Users
Get-AzureADUser -All $true
Get-AzureADUser -All $true | select UserPrincipalName
# Get info of 1 user
Get-AzureADUser -ObjectId test@corp.onmicrosoft.com | fl
# Search "admin" users
Get-AzureADUser -SearchString "admin" #Search admin at the begining of DisplayName or userPrincipalName
Get-AzureADUser -All $true |?{$_.Displayname -match "admin"} #Search "admin" word in DisplayName
# Get all attributes of a user
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com|%{$_.PSObject.Properties.Name}
# Search attributes containing the word "password"
Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $($Properties.$_)"}}}
# All users from AzureAD# All users from AzureAD
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
# All users synced from on-prem
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
# Objects created by a/any user
Get-AzureADUser [-ObjectId <email>] | Get-AzureADUserCreatedObject
# Devices owned by a user
Get-AzureADUserOwnedDevice -ObjectId test@corp.onmicrosoft.com
# Objects owned by a specific user
Get-AzureADUserOwnedObject -ObjectId test@corp.onmicrosoft.com
# Get groups & roles where the user is a member
Get-AzureADUserMembership -ObjectId 'test@corp.onmicrosoft.com'
# Get devices owned by a user
Get-AzureADUserOwnedDevice -ObjectId test@corp.onmicrosoft.com
# Get devices registered by a user
Get-AzureADUserRegisteredDevice -ObjectId test@defcorphq.onmicrosoft.com
# Apps where a user has a role (role not shown)
Get-AzureADUser -ObjectId roygcain@defcorphq.onmicrosoft.com | Get-AzureADUserAppRoleAssignment | fl *
# Get Administrative Units of a user
$userObj = Get-AzureADUser -Filter "UserPrincipalName eq 'bill@example.com'"
Get-AzureADMSAdministrativeUnit | where { Get-AzureADMSAdministrativeUnitMember -Id $_.Id | where { $_.Id -eq $userObj.ObjectId } }
```

{{#endtab }}

{{#tab name="Az" }}

```bash
# Enumerate users
Get-AzADUser
# Get details of a user
Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com
# Search user by string
Get-AzADUser -SearchString "admin" #Search at the beginnig of DisplayName
Get-AzADUser | ?{$_.Displayname -match "admin"}
# Get roles assigned to a user
Get-AzRoleAssignment -SignInName test@corp.onmicrosoft.com
```

{{#endtab }}
{{#endtabs }}

#### Change User Password

```bash
$password = "ThisIsTheNewPassword.!123" | ConvertTo- SecureString -AsPlainText –Force

(Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "victim@corp.onmicrosoft.com"}).ObjectId | Set- AzureADUserPassword -Password $password –Verbose
```

### MFA & Conditional Access Policies

It's highly recommended to add MFA to every user, however, some companies won't set it or might set it with a Conditional Access: The user will be **required MFA if** it logs in from an specific location, browser or **some condition**. These policies, if not configured correctly might be prone to **bypasses**. Check:

### Groups

For more information about Entra ID groups check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# Enumerate groups
az ad group list
az ad group list --query "[].[displayName]" -o table
# Get info of 1 group
az ad group show --group <group>
# Get "admin" groups
az ad group list --query "[].displayName" | findstr /i "admin"
az ad group list --query "[?contains(displayName,'admin')].displayName"
# All groups from Entra ID
az ad group list --query "[].{osi:onPremisesSecurityIdentifier,displayName:displayName,description:description}[?osi==null]"
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
# All groups synced from on-prem
az ad group list --query "[].{osi:onPremisesSecurityIdentifier,displayName:displayName,description:description}[?osi!=null]"
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"
# Get members of group
az ad group member list --group <group> --query "[].userPrincipalName" -o table
# Check if member of group
az ad group member check --group "VM Admins" --member-id <id>
# Get which groups a group is member of
az ad group get-member-groups -g "VM Admins"
# Get roles assigned to the group in Azure (NOT in Entra ID)
az role assignment list --include-groups --include-classic-administrators true --assignee <group-id>

# To get Entra ID roles assigned check how it's done with users and use a group ID
```

{{#endtab }}

{{#tab name="Az" }}

```bash
# Get all groups
Get-AzADGroup
# Get details of a group
Get-AzADGroup -ObjectId <id>
# Search group by string
Get-AzADGroup -SearchString "admin" | fl * #Search at the beginnig of DisplayName
Get-AzADGroup |?{$_.Displayname -match "admin"}
# Get members of group
Get-AzADGroupMember -GroupDisplayName <resource_group_name>
# Get roles of group
Get-AzRoleAssignment -ResourceGroupName <resource_group_name>
```

{{#endtab }}
{{#tab name="MS Graph" }}

```bash
# Enumerate groups using Microsoft Graph PowerShell
Get-MgGroup -All

# Get group details
Get-MgGroup -GroupId <GroupId> | Format-List *

# Search "admin" groups
Get-MgGroup -All | Where-Object { $_.DisplayName -like "*admin*" } | Select-Object DisplayName

# Get members of a group
Get-MgGroupMember -GroupId <GroupId> -All

# Get groups a group is member of
Get-MgGroupMemberOf -GroupId <GroupId>

# Get roles assigned to the group in Entra ID
Get-MgGroupAppRoleAssignment -GroupId <GroupId>

# Get group owner
Get-MgGroupOwner -GroupId <GroupId>

# List available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph.Groups
```
{{#endtab }}
{{#tab name="Azure AD" }}

```bash
# Enumerate Groups
Get-AzureADGroup -All $true
# Get info of 1 group
Get-AzADGroup -DisplayName <resource_group_name> | fl
# Get "admin" groups
Get-AzureADGroup -SearchString "admin" | fl #Groups starting by "admin"
Get-AzureADGroup -All $true |?{$_.Displayname -match "admin"} #Groups with the word "admin"
# Get groups allowing dynamic membership
Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}
# All groups that are from Azure AD
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
# All groups that are synced from on-prem (note that security groups are not synced)
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
# Get members of a group
Get-AzureADGroupMember -ObjectId <group_id>
# Get roles of group
Get-AzureADMSGroup -SearchString "Contoso_Helpdesk_Administrators" #Get group id
Get-AzureADMSRoleAssignment -Filter "principalId eq '69584002-b4d1-4055-9c94-320542efd653'"
# Get Administrative Units of a group
$groupObj = Get-AzureADGroup -Filter "displayname eq 'TestGroup'"
Get-AzureADMSAdministrativeUnit | where { Get-AzureADMSAdministrativeUnitMember -Id $_.Id | where {$_.Id -eq $groupObj.ObjectId} }
# Get Apps where a group has a role (role not shown)
Get-AzureADGroup -ObjectId <id> | Get-AzureADGroupAppRoleAssignment | fl *
```

{{#endtab }}
{{#endtabs }}

#### Add user to group

Owners of the group can add new users to the group

```bash
Add-AzureADGroupMember -ObjectId <group_id> -RefObjectId <user_id> -Verbose
```

> [!WARNING]
> Groups can be dynamic, which basically means that **if a user fulfil certain conditions it will be added to a group**. Of course, if the conditions are based in **attributes** a **user** can **control**, he could abuse this feature to **get inside other groups**.\
> Check how to abuse dynamic groups in the following page:

### Service Principals

For more information about Entra ID service principals check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# Get Service Principals
az ad sp list --all
az ad sp list --all --query "[].[displayName,appId]" -o table
# Get details of one SP
az ad sp show --id 00000000-0000-0000-0000-000000000000
# Search SP by string
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
# Get owner of service principal
az ad sp owner list --id <id> --query "[].[displayName]" -o table
# Get service principals owned by the current user
az ad sp list --show-mine

# Get SPs with generated secret or certificate
az ad sp list --query '[?length(keyCredentials) > `0` || length(passwordCredentials) > `0`].[displayName, appId, keyCredentials, passwordCredentials]' -o json
```

{{#endtab }}

{{#tab name="Az" }}

```bash
# Get SPs
Get-AzADServicePrincipal
# Get info of 1 SP
Get-AzADServicePrincipal -ObjectId <id>
# Search SP by string
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"}
# Get roles of a SP
Get-AzRoleAssignment -ServicePrincipalName <String>
```

{{#endtab }}

{{#tab name="Raw" }}

```bash
$Token = 'eyJ0eX..'
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
  Method  = 'GET'
  Uri     = $URI
  Headers = @{
      'Authorization' = "Bearer $Token"
  }
}
(Invoke-RestMethod @RequestParams).value
```

{{#endtab }}
{{#tab name="MS Graph" }}

```bash
# Get Service Principals using Microsoft Graph PowerShell
Get-MgServicePrincipal -All

# Get details of one Service Principal
Get-MgServicePrincipal -ServicePrincipalId <ServicePrincipalId> | Format-List *

# Search SP by display name
Get-MgServicePrincipal -All | Where-Object { $_.DisplayName -like "*app*" } | Select-Object DisplayName

# Get owner of Service Principal
Get-MgServicePrincipalOwner -ServicePrincipalId <ServicePrincipalId>

# Get objects owned by a Service Principal
Get-MgServicePrincipalOwnedObject -ServicePrincipalId <ServicePrincipalId>

# Get groups where the SP is a member
Get-MgServicePrincipalMemberOf -ServicePrincipalId <ServicePrincipalId>

# List available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph.ServicePrincipals
```
{{#endtab }}

{{#tab name="Azure AD" }}

```bash
# Get Service Principals
Get-AzureADServicePrincipal -All $true
# Get details about a SP
Get-AzureADServicePrincipal -ObjectId <id> | fl *
# Get SP by string name or Id
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"} | fl
Get-AzureADServicePrincipal -All $true | ?{$_.AppId -match "103947652-1234-5834-103846517389"}
# Get owner of SP
Get-AzureADServicePrincipal -ObjectId <id> | Get-AzureADServicePrincipalOwner |fl *
# Get objects owned by a SP
Get-AzureADServicePrincipal -ObjectId <id> | Get-AzureADServicePrincipalOwnedObject
# Get objects created by a SP
Get-AzureADServicePrincipal -ObjectId <id> | Get-AzureADServicePrincipalCreatedObject
# Get groups where the SP is a member
Get-AzureADServicePrincipal | Get-AzureADServicePrincipalMembership
Get-AzureADServicePrincipal -ObjectId <id> | Get-AzureADServicePrincipalMembership |fl *
```

{{#endtab }}
{{#endtabs }}

> [!WARNING]
> The Owner of a Service Principal can change its password.

<details>

<summary>List and try to add a client secret on each Enterprise App</summary>

```bash
# Just call Add-AzADAppSecret
Function Add-AzADAppSecret
{
<#
    .SYNOPSIS
        Add client secret to the applications.

    .PARAMETER GraphToken
        Pass the Graph API Token

    .EXAMPLE
        PS C:\> Add-AzADAppSecret -GraphToken 'eyJ0eX..'

    .LINK
        https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http
        https://docs.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http
#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$True)]
    [String]
    $GraphToken = $null
    )

    $AppList = $null
    $AppPassword = $null

    # List All the Applications

    $Params = @{
     "URI"     = "https://graph.microsoft.com/v1.0/applications"
     "Method"  = "GET"
     "Headers" = @{
     "Content-Type"  = "application/json"
     "Authorization" = "Bearer $GraphToken"
     }
    }

    try
    {
        $AppList = Invoke-RestMethod @Params -UseBasicParsing
    }
    catch
    {
    }

    # Add Password in the Application

    if($AppList -ne $null)
    {
        [System.Collections.ArrayList]$Details = @()

        foreach($App in $AppList.value)
        {
            $ID = $App.ID
            $psobj = New-Object PSObject

            $Params = @{
             "URI"     = "https://graph.microsoft.com/v1.0/applications/$ID/addPassword"
             "Method"  = "POST"
             "Headers" = @{
             "Content-Type"  = "application/json"
             "Authorization" = "Bearer $GraphToken"
             }
            }

            $Body = @{
              "passwordCredential"= @{
                "displayName" = "Password"
              }
            }

            try
            {
                $AppPassword = Invoke-RestMethod @Params -UseBasicParsing -Body ($Body | ConvertTo-Json)
                Add-Member -InputObject $psobj -NotePropertyName "Object ID" -NotePropertyValue $ID
                Add-Member -InputObject $psobj -NotePropertyName "App ID" -NotePropertyValue $App.appId
                Add-Member -InputObject $psobj -NotePropertyName "App Name" -NotePropertyValue $App.displayName
                Add-Member -InputObject $psobj -NotePropertyName "Key ID" -NotePropertyValue $AppPassword.keyId
                Add-Member -InputObject $psobj -NotePropertyName "Secret" -NotePropertyValue $AppPassword.secretText
                $Details.Add($psobj) | Out-Null
            }
            catch
            {
                Write-Output "Failed to add new client secret to '$($App.displayName)' Application."
            }
        }
        if($Details -ne $null)
        {
            Write-Output ""
            Write-Output "Client secret added to : "
            Write-Output $Details | fl *
        }
    }
    else
    {
       Write-Output "Failed to Enumerate the Applications."
    }
}
```

</details>

### Applications

For more information about Applications check:

When an App is generated 3 types of permissions are given:

- **Permissions** given to the **Service Principal** (via roles).
- **Permissions** the **app** can have and use on **behalf of the user**.
- **API Permissions** that gives the app permissions over EntraID withuot requiring other roles granting these permissions.

{{#tabs }}
{{#tab name="az cli" }}

```bash
# List Apps
az ad app list
az ad app list --query "[].[displayName,appId]" -o table
# Get info of 1 App
az ad app show --id 00000000-0000-0000-0000-000000000000
# Search App by string
az ad app list --query "[?contains(displayName,'app')].displayName"
# Get the owner of an application
az ad app owner list --id <id> --query "[].[displayName]" -o table
# Get SPs owned by current user
az ad app list --show-mine
# Get apps with generated secret or certificate
az ad app list --query '[?length(keyCredentials) > `0` || length(passwordCredentials) > `0`].[displayName, appId, keyCredentials, passwordCredentials]' -o json
# Get Global Administrators (full access over apps)
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles/1b2256f9-46c1-4fc2-a125-5b2f51bb43b7/members"
# Get Application Administrators (full access over apps)
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles/1e92c3b7-2363-4826-93a6-7f7a5b53e7f9/members"
# Get Cloud Applications Administrators (full access over apps)
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles/0d601d27-7b9c-476f-8134-8e7cd6744f02/members"

# Get "API Permissions" of an App
## Get the ResourceAppId
az ad app show --id "<app-id>" --query "requiredResourceAccess" --output json
