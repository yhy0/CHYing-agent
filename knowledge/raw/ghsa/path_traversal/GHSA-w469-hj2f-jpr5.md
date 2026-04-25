# Harness Allows Arbitrary File Write in Gitness LFS server

**GHSA**: GHSA-w469-hj2f-jpr5 | **CVE**: CVE-2025-58158 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22, CWE-73

**Affected Packages**:
- **github.com/harness/gitness** (go): >= 1.0.4, < 3.3.0
- **github.com/harness/gitness** (go): < 1.0.4-gitspaces-beta.0.20250808064055-21c5ce42ae13

## Description

### Impact
Open Source Harness git LFS server (Gitness)  exposes api to retrieve and upload files via git LFS.  Implementation of upload git LFS file api is vulnerable to arbitrary file write.  Due to improper sanitization for upload path, a malicious authenticated user who has access to Harness Gitness server api can use a crafted upload request to write arbitrary file to any location on file system, may even compromise the server. 

Users using git LFS are vulnerable.

### Patches
Users have to upgrade to v3.3.0 . All previous versions are affected by this vulnerability.
