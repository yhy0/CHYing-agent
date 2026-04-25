# Jenkins Applitools Eyes Plugin vulnerable to XSS through its Build page

**GHSA**: GHSA-j4wf-9gx8-63f8 | **CVE**: CVE-2025-53658 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.plugins:applitools-eyes** (maven): <= 1.16.5

## Description

Jenkins Applitools Eyes Plugin 1.16.5 and earlier does not escape the Applitools URL on the build page.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.

Applitools Eyes Plugin 1.16.6 rejects Applitools URLs that contain HTML metacharacters.
