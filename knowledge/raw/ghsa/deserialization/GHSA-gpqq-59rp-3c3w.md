# Apache InLong vulnerable to JDBC Deserialization of Untrusted Data

**GHSA**: GHSA-gpqq-59rp-3c3w | **CVE**: CVE-2023-27296 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.inlong:inlong-manager** (maven): >= 1.1.0, < 1.6.0

## Description

Apache InLong versions from 1.1.0 through 1.5.0 are vulnerable to Java Database Connectivity (JDBC) deserialization of untrusted data from the MySQL JDBC URL in MySQLDataNode. It could be triggered by authenticated users of InLong. This has been patched in version 1.6.0. Users are advised to upgrade to Apache InLong's latest version or cherry-pick the [patch](https://github.com/apache/inlong/pull/7422) to solve it.
