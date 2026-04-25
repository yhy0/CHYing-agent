# Apache Zeppelin remote code execution by adding malicious JDBC connection string

**GHSA**: GHSA-66j8-c83m-gj5f | **CVE**: CVE-2024-31864 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.apache.zeppelin:zeppelin-jdbc** (maven): < 0.11.1

## Description

Improper Control of Generation of Code ('Code Injection') vulnerability in Apache Zeppelin.

The attacker can inject sensitive configuration or malicious code when connecting MySQL database via JDBC driver. This issue affects Apache Zeppelin: before 0.11.1.

Users are recommended to upgrade to version 0.11.1, which fixes the issue.
