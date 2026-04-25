# Jenkins Build Failure Analyzer Plugin Cross-site Scripting vulnerability

**GHSA**: GHSA-262f-77q5-rqv6 | **CVE**: CVE-2023-43499 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **com.sonyericsson.jenkins.plugins.bfa:build-failure-analyzer** (maven): < 2.4.2

## Description

Jenkins Build Failure Analyzer Plugin 2.4.1 and earlier does not escape Failure Cause names in build logs.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to create or update Failure Causes.

Build Failure Analyzer Plugin 2.4.2 escapes Failure Cause names in build logs.
