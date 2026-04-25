# Improper escaping in Apache Zeppelin

**GHSA**: GHSA-86jx-wr74-xr74 | **CVE**: CVE-2024-31866 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-116

**Affected Packages**:
- **org.apache.zeppelin:zeppelin-interpreter** (maven): >= 0.8.2, < 0.11.1

## Description

Improper Encoding or Escaping of Output vulnerability in Apache Zeppelin.

The attackers can execute shell scripts or malicious code by overriding configuration like ZEPPELIN_INTP_CLASSPATH_OVERRIDES.
This issue affects Apache Zeppelin: from 0.8.2 before 0.11.1.

Users are recommended to upgrade to version 0.11.1, which fixes the issue.
