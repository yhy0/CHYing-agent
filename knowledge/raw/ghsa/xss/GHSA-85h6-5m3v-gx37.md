# Jenkins has a stored XSS vulnerability in node offline cause description

**GHSA**: GHSA-85h6-5m3v-gx37 | **CVE**: CVE-2026-27099 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.542, < 2.551
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.483, < 2.541.2

## Description

Jenkins 2.483 through 2.550 (both inclusive), LTS 2.492.1 through 2.541.1 (both inclusive) does not escape the user-provided description of the "Mark temporarily offline" offline cause, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Agent/Configure or Agent/Disconnect permission.
