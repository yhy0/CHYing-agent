# Apache Cassandra: User with MODIFY permission on ALL KEYSPACES can escalate privileges to superuser via unsafe actions

**GHSA**: GHSA-wmcc-9vch-jmx4 | **CVE**: CVE-2025-23015 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-267

**Affected Packages**:
- **org.apache.cassandra:cassandra-all** (maven): >= 5.0-alpha1, < 5.0.3
- **org.apache.cassandra:cassandra-all** (maven): >= 4.1-alpha1, < 4.1.8
- **org.apache.cassandra:cassandra-all** (maven): >= 4.0-alpha1, < 4.0.16
- **org.apache.cassandra:cassandra-all** (maven): >= 3.1, < 3.11.18
- **org.apache.cassandra:cassandra-all** (maven): < 3.0.31

## Description

Privilege Defined With Unsafe Actions vulnerability in Apache Cassandra. An user with MODIFY permission ON ALL KEYSPACES can escalate privileges to superuser within a targeted Cassandra cluster via unsafe actions to a system resource. Operators granting data MODIFY permission on all keyspaces on affected versions should review data access rules for potential breaches.

This issue affects Apache Cassandra through 3.0.30, 3.11.17, 4.0.15, 4.1.7, 5.0.2.

Users are recommended to upgrade to versions 3.0.31, 3.11.18, 4.0.16, 4.1.8, 5.0.3, which fixes the issue.
