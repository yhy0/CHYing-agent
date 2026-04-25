# Apache Seata Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-3xq2-w6j4-c99r | **CVE**: CVE-2024-22399 | **Severity**: critical (CVSS 8.1)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.seata:seata-core** (maven): >= 1.0.0, < 1.8.1
- **org.apache.seata:seata-core** (maven): = 2.0.0

## Description

Deserialization of Untrusted Data vulnerability in Apache Seata. 

When developers disable authentication on the Seata-Server and do not use the Seata client SDK dependencies, they may construct uncontrolled serialized malicious requests by directly sending bytecode based on the Seata private protocol.

This issue affects Apache Seata: 2.0.0, from 1.0.0 through 1.8.0.

Users are recommended to upgrade to version 2.1.0/1.8.1, which fixes the issue.
