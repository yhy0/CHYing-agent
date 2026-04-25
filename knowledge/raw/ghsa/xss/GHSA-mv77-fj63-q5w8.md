# Stored XSS vulnerability in Jenkins GitHub Plugin

**GHSA**: GHSA-mv77-fj63-q5w8 | **CVE**: CVE-2023-46650 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **com.coravy.hudson.plugins.github:github** (maven): < 1.37.3.1

## Description

Jenkins GitHub Plugin 1.37.3 and earlier does not escape the GitHub project URL on the build page when showing changes.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.

GitHub Plugin 1.37.3.1 escapes GitHub project URL on the build page when showing changes.
