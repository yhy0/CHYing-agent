# kcp allows unauthorized creation and deletion of objects in arbitrary workspaces through APIExport Virtual Workspace

**GHSA**: GHSA-w2rr-38wv-8rrp | **CVE**: CVE-2025-29922 | **Severity**: critical (CVSS 9.6)

**CWE**: CWE-285

**Affected Packages**:
- **github.com/kcp-dev/kcp** (go): < 0.26.3

## Description

### Impact

The `APIExport` Virtual Workspace can be used to manage objects in workspaces that bind that `APIExport` for resources defined in the `APIExport` or specified and accepted via permission claims. This allows an API provider (via their `APIExport`) scoped down access to workspaces of API consumers to provide their services properly.

The identified vulnerability allows creating or deleting an object via the `APIExport` VirtualWorkspace in any arbitrary target workspace for pre-existing resources. By design, this should only be allowed when the workspace owner decides to give access to an API provider by creating an APIBinding.

With this vulnerability, it is possible for an attacker to create and delete objects even if none of these requirements are satisfied, i.e. even if there is no APIBinding in that workspace at all or the workspace owner has created an APIBinding, but rejected a permission claim.

### Patches

A fix for this issue has been identified and has been published with kcp 0.26.3 and 0.27.0.

### Workarounds

For users unable to upgrade to one of the patched versions, the following guidance can be given:

- Minimise the set of people with `apiexport/content` sub-resource access to `APIExport` resources. Be aware that this has to apply to all workspaces to be effective.
- Filter incoming requests in a reverse proxy with a similar logic as the authorizer added in the referenced pull request.

### References

See pull request (https://github.com/kcp-dev/kcp/pull/3338).
