# Chall-Manager is vulnerable to Path Traversal when extracting/decoding a zip archive

**GHSA**: GHSA-3gv2-v3jx-r9fh | **CVE**: CVE-2025-53632 | **Severity**: high (CVSS 9.1)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/ctfer-io/chall-manager** (go): < 0.1.4

## Description

### Impact
When decoding a scenario (i.e. a zip archive), the path of the file to write is not checked, potentially leading to zip slips.
Exploitation does not require authentication nor authorization, so anyone can exploit it. It should nonetheless not be exploitable as it is **highly** recommended to bury Chall-Manager deep within the infrastructure due to its large capabilities, so no users could reach the system.

### Patches
Patch has been implemented by [commit `47d188f`](https://github.com/ctfer-io/chall-manager/commit/47d188fda5e3f86285e820f12ad9fb6f9930662c) and shipped in [`v0.1.4`](https://github.com/ctfer-io/chall-manager/releases/tag/v0.1.4).

### Workarounds
No workaround exist.

### References
N/A.
