# Go-huge-util vulnerable to path traversal when unzipping files

**GHSA**: GHSA-5g39-ppwg-6xx8 | **CVE**: CVE-2023-28105 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/dablelv/go-huge-util** (go): < 0.0.34

## Description

Impact
ZipSlip issue when use fsutil package to unzip files.
When users use zip.Unzip to unzip zip files from a malicious attacker, they may be vulnerable to path traversal.

Patches
It has been fixed in v0.0.34, Please upgrade version to v0.0.34 or above.

Workarounds
No, users have to upgrade version.

Specific Go Packages Affected
github.com/dablelv/go-huge-util/zip

References
