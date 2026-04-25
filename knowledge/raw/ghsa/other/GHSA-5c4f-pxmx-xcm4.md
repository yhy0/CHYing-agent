# Apache Cassandra: User with MODIFY permission on ALL KEYSPACES can escalate privileges to superuser via unsafe actions (4.0.16 only)

**GHSA**: GHSA-5c4f-pxmx-xcm4 | **CVE**: CVE-2025-26467 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-267

**Affected Packages**:
- **org.apache.cassandra:cassandra-all** (maven): = 4.0.16

## Description

Privilege Defined With Unsafe Actions vulnerability in Apache Cassandra. An user with MODIFY permission ON ALL KEYSPACES can escalate privileges to superuser within a targeted Cassandra cluster via unsafe actions to a system resource. Operators granting data MODIFY permission on all keyspaces on affected versions should review data access rules for potential breaches.



This issue affects Apache Cassandra 3.0.30, 3.11.17, 4.0.16, 4.1.7, 5.0.2, but this advisory is only for 4.0.16 because the fix to CVE-2025-23015 was incorrectly applied to 4.0.16, so that version is still affected.

Users in the 4.0 series are recommended to upgrade to version 4.0.17 which fixes the issue. Users from 3.0, 3.11, 4.1 and 5.0 series should follow recommendation from CVE-2025-23015.
