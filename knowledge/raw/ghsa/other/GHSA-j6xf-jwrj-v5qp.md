# Coder vulnerable to privilege escalation could lead to a cross workspace compromise

**GHSA**: GHSA-j6xf-jwrj-v5qp | **CVE**: CVE-2025-58437 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-269, CWE-277, CWE-613

**Affected Packages**:
- **github.com/coder/coder/v2** (go): >= 2.22.0, < 2.24.4
- **github.com/coder/coder/v2** (go): >= 2.25.0, < 2.25.2

## Description

## Summary

Insecure session handling opened room for a privilege escalation scenario in which [prebuilt workspaces](https://coder.com/docs/admin/templates/extending-templates/prebuilt-workspaces) could be compromised by abusing a shared system identity.

## Details

Coder automatically generates a session token for a user when a workspace is started. It is automatically exposed via [`coder_workspace_owner.session_token`](https://registry.terraform.io/providers/coder/coder/latest/docs/data-sources/workspace_owner#session_token-1). Prebuilt workspaces are initially owned by a built-in `prebuilds` system user. 

When a prebuilt workspace is claimed, a new session token is generated for the user that claimed the workspace, but the previous session token for the `prebuilds` user was not expired. Any Coder workspace templates that persist this automatically generated session token are potentially impacted. 

For example, the [coder-login module](https://github.com/coder/registry/blob/8677e7d52b374b025c4820d09049dc6b008beee8/registry/coder/modules/coder-login/run.sh) allows template authors to automatically configure the coder CLI to be authenticated with the Coder deployment.

This causes a script to be run on workspace startup that runs the command `coder login` using the automatically generated user session token c.f. [https://github.com/coder/registry/blob/8677e7d52b374b025c4820d09049dc6b008beee8/registry/coder/modules/coder-login/main.tf#L23](https://github.com/coder/registry/blob/8677e7d52b374b025c4820d09049dc6b008beee8/registry/coder/modules/coder-login/main.tf#L23)

This module was originally written before the inception of the [prebuilds](https://coder.com/docs/admin/templates/extending-templates/prebuilt-workspaces) feature in Coder, which essentially creates a "pre-warmed" pool of workspaces owned by a particular `prebuilds` system user.

When this module is invoked on a prebuilt workspace, it causes the Coder CLI inside the workspace to persist the session token for the `prebuilds` user to disk. Because the `coder-login` module checks if the CLI is authenticated, the script exits early before updating the session token, leaving the Coder CLI authenticated as the `prebuilds`user upon claim:

## Impact

> Important: **Deployments that have never utilized the [prebuilds](https://coder.com/docs/admin/templates/extending-templates/prebuilt-workspaces) feature are not affected by this vulnerability.**


This vulnerability requires a previously authenticated user to claim a prebuilt workspace from a template configured to store the prebuilds user session token as described above.

The `prebuilds` user has no specific roles, so its credential has the same level of access as a regular member user, meaning a user with the `prebuilds` user's credential can move laterally to any other prebuilt workspace, or create new workspaces as the `prebuilds` user.

This means that a malicious authenticated actor can potentially execute code on other workspaces owned by the `prebuilds` user and potentially access information of other users once they claim a previously poisoned workspace.


## Remediation

Fixed in https://github.com/coder/coder/pull/19667

Note that prebuilt workspaces claimed previous to the fix may have been affected by this vulnerability. It is recommended that users re-create their workspace if it was created from a prebuild.

To identify potentially affected workspaces, run the following SQL query against the Coder database:

```sql
SELECT w.id, w.name, w.owner_id, u.email
FROM workspaces w
LEFT JOIN users u ON u.id = w.owner_id
WHERE w.owner_id <> 'c42fdf75-3097-471c-8c33-fb52454d81c0'::uuid
  AND NOT w.deleted
  AND EXISTS (
    SELECT 1
    FROM workspace_builds AS wb
    WHERE wb.workspace_id = w.id
      AND wb.initiator_id = 'c42fdf75-3097-471c-8c33-fb52454d81c0'::uuid
  );
```

> Previous manually created tokens for the prebuilds user are left as-is. You may wish to review these via `coder tokens list --all`

---

[Premium license](https://coder.com/docs/admin/licensing) customers can also take advantage of the [audit logs](https://coder.com/docs/admin/security/audit-logs) feature to query actions performed by the `prebuilds` user.

Following [filter](https://coder.com/docs/admin/security/audit-logs#how-to-filter-audit-logs) can be used to verify if no [API keys](https://coder.com/docs/reference/api/users#create-token-api-key) were created by the `prebuilds` user
> would indicate a potentially malicious action aimed at achieving [persistence](https://attack.mitre.org/tactics/TA0003/)
```
username:prebuilds resource_type:api_key
```

Following [filter](https://coder.com/docs/admin/security/audit-logs#how-to-filter-audit-logs) can be used to list all *write* operations performed by the `prebuilds` user (including failed attempts to update various settings)
```
username:prebuilds action:write
```

### Patched versions
- [2.24.4](https://github.com/coder/coder/releases/tag/v2.24.4)
- [2.25.2](https://github.com/coder/coder/releases/tag/v2.25.2)
- [2.26.0](https://github.com/coder/coder/releases/tag/v2.26.0)
