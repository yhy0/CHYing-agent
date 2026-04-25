# Goutil vulnerable to path traversal when unzipping files

**GHSA**: GHSA-fx2v-qfhr-4chv | **CVE**: CVE-2023-27475 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/gookit/goutil** (go): < 0.6.0

## Description

### Impact

ZipSlip issue when use fsutil package to unzip files.
When users use fsutil.Unzip to unzip zip files from a malicious attacker, they may be vulnerable to path traversal. 

### Patches

It has been fixed in v0.6.0, Please upgrade version to v0.6.0 or above.

### Workarounds
No, users have to upgrade version.
