# lakeFS vulnerable to path traversal in local block adapter allow cross-namespace and sibling directory access

**GHSA**: GHSA-699m-4v95-rmpm | **CVE**: CVE-2026-26187 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/treeverse/lakefs** (go): <= 1.76.0

## Description

## Summary

Two path traversal vulnerabilities in the local block adapter allow authenticated users to read and write files outside their designated storage boundaries.

## Details

The local block adapter in `pkg/block/local/adapter.go` had two path traversal vulnerabilities:

### 1. Prefix Bypass Vulnerability

The `verifyRelPath` function used `strings.HasPrefix()` to verify that requested paths fall within the configured storage directory. This check was insufficient because it validated only the path prefix without requiring a path separator, allowing access to sibling directories with similar names.

**Example:** If the adapter is configured with base path `/data/lakefs`:

| Path | Expected | Actual |
|------|----------|--------|
| `/data/lakefs/valid/file.txt` | Allowed | Allowed |
| `/data/lakefs_evil/secret.txt` | Blocked | **Vulnerable** |
| `/data/lakefs_backup/data.db` | Blocked | **Vulnerable** |

### 2. Namespace Escape via Identifier

The adapter verified that resolved paths stayed within the adapter's base path, but did not verify that object identifiers stayed within their designated storage namespace. This allowed attackers to use path traversal sequences in the object identifier to access files in other namespaces.

**Example:** With base path `/data/lakefs` and namespace `local://repo1/userdata`:

| Identifier | Resolved Path | Expected | Actual |
|------------|---------------|----------|--------|
| `file.txt` | `/data/lakefs/repo1/userdata/file.txt` | Allowed | Allowed |
| `../secrets/key.txt` | `/data/lakefs/repo1/secrets/key.txt` | Blocked | **Vulnerable** |
| `../../other-repo/data.txt` | `/data/lakefs/other-repo/data.txt` | Blocked | **Vulnerable** |

This vulnerability allows users with access to one namespace to read and write files in other namespaces within the same lakeFS deployment.

## Impact

Authenticated lakeFS users can:

- **Read and write files in sibling directories** that share the same path prefix as the storage directory (vulnerability 1)
- **Access files across namespaces** by using path traversal in object identifiers (vulnerability 2)

This could allow attackers to:

- Read sensitive data from other repositories/namespaces
- Write malicious files to other namespaces
- Read/write files in adjacent directories outside lakeFS storage
- Potentially escalate privileges if writable directories are used by other services

This vulnerability **only affects** deployments using the local block adapter. Deployments using S3, GCS, Azure, or other object storage backends are **not affected**.

## Patches

Fixed in version v1.77.0.

The fixes:
1. Append a path separator to prefix checks, ensuring paths must be within the storage directory
2. Add two-level path validation: verify both that namespace paths stay within the adapter's base path AND that resolved paths stay within their designated namespace

## Workarounds

- Configure the storage path with a unique name unlikely to be a prefix of other directories
- Restrict filesystem permissions for the lakeFS process
- Ensure no sensitive data exists in sibling directories

## Credit

Discovered via CodeQL static analysis.
