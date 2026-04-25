# OpenAPI Generator Online - Arbitrary File Read/Delete

**GHSA**: GHSA-g3hr-p86p-593h | **CVE**: CVE-2024-35219 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-22

**Affected Packages**:
- **org.openapitools:openapi-generator-online** (maven): < 7.6.0

## Description

### Impact
Attackers can exploit the vulnerability to read and delete files and folders from an arbitrary, writable directory as anyone can set the output folder when submitting the request via the `outputFolder` option.

### Patches
The issue was fixed via https://github.com/OpenAPITools/openapi-generator/pull/18652 (included in v7.6.0 release)  by removing the usage of the `outputFolder` option.

### Workarounds
No workaround available.

### References
No other reference available.
