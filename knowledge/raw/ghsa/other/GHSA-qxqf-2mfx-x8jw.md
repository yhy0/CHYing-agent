# veraPDF has potential XSLT injection vulnerability when using policy files

**GHSA**: GHSA-qxqf-2mfx-x8jw | **CVE**: CVE-2024-28109 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-91

**Affected Packages**:
- **org.verapdf:core** (maven): < 1.24.2
- **org.verapdf:core-jakarta** (maven): < 1.24.2
- **org.verapdf:core-arlington** (maven): < 1.25.127
- **org.verapdf:verapdf-library-arlington** (maven): < 1.25.127
- **org.verapdf:verapdf-library** (maven): < 1.24.2
- **org.verapdf:verapdf-library-jakarta** (maven): < 1.24.2

## Description

### Impact

Executing policy checks using custom schematron files invokes an XSL transformation that may theoretically lead to a remote code execution (RCE) vulnerability.

### Patches

This has been patched and users should upgrade to veraPDF v1.24.2

### Workarounds

This doesn't affect the standard validation and policy checks functionality, veraPDF's common use cases. Most veraPDF users don't insert any custom XSLT code into policy profiles, which are based on Schematron syntax rather than direct XSL transforms. For users who do, only load custom policy files from sources you trust.

### References

Original issue: <https://github.com/veraPDF/veraPDF-library/issues/1415>

