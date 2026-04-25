# mrpack-install vulnerable to path traversal with dependency

**GHSA**: GHSA-r887-gfxh-m9rr | **CVE**: CVE-2023-25307 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/nothub/mrpack-install** (go): <= 0.16.2

## Description

### Impact
Importing a malicious `.mrpack` file can cause path traversal while downloading files.
This can lead to scripts or config files being placed or replaced at arbitrary locations, without the user noticing.

### Patches
No patches yet.

### Workarounds
Avoid importing `.mrpack` files from untrusted sources.

### References
https://docs.modrinth.com/docs/modpacks/format_definition/#files

