# rudder-server is vulnerable to SQL injection

**GHSA**: GHSA-3jmm-f6jj-rcc3 | **CVE**: CVE-2023-30625 | **Severity**: critical (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/rudderlabs/rudder-server** (go): < 1.3.0-rc.1

## Description

rudder-server is part of RudderStack, an open source Customer Data Platform (CDP). Versions of rudder-server prior to 1.3.0-rc.1 are vulnerable to SQL injection. This issue may lead to Remote Code Execution (RCE) due to the `rudder` role in PostgresSQL having superuser permissions by default. Version 1.3.0-rc.1 contains patches for this issue.
