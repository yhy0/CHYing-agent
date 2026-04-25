# Jenkins Flaky Test Handler Plugin stored cross-site scripting vulnerability

**GHSA**: GHSA-hv48-hgp6-xpqf | **CVE**: CVE-2023-40342 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.plugins:flaky-test-handler** (maven): < 1.2.3

## Description

Jenkins Flaky Test Handler Plugin 1.2.2 and earlier does not escape JUnit test contents when showing them on the Jenkins UI.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control JUnit report file contents.

Flaky Test Handler Plugin 1.2.3 escapes JUnit test contents when showing them on the Jenkins UI.
