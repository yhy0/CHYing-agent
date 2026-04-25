# pgAdmin4 vulnerable to Remote Code Execution (RCE) when running in server mode

**GHSA**: GHSA-w2p4-p4rh-qcm3 | **CVE**: CVE-2025-12762 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-94

**Affected Packages**:
- **pgadmin4** (pip): < 9.10

## Description

pgAdmin versions up to 9.9 are affected by a Remote Code Execution (RCE) vulnerability that occurs when running in server mode and performing restores from PLAIN-format dump files. This issue allows attackers to inject and execute arbitrary commands on the server hosting pgAdmin, posing a critical risk to the integrity and security of the database management system and underlying data.
