# Apache Seata Vulnerable to Deserialization of Untrusted Data

**GHSA**: GHSA-m964-fjrh-xxq2 | **CVE**: CVE-2025-32897 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.seata:seata-config-core** (maven): >= 2.0.0, < 2.3.0

## Description

Deserialization of Untrusted Data vulnerability in Apache Seata (incubating).

This security vulnerability is the same as CVE-2024-47552, but the version range described in the CVE-2024-47552 definition is too narrow.
This issue affects Apache Seata (incubating): from 2.0.0 before 2.3.0.

Users are recommended to upgrade to version 2.3.0, which fixes the issue.
