# Apache Pyfory python is vulnerable to deserialization of untrusted data

**GHSA**: GHSA-538v-3wq9-4h3r | **CVE**: CVE-2025-61622 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **pyfory** (pip): >= 0.12.0, < 0.12.3
- **pyfury** (pip): >= 0.1.0, <= 0.10.3

## Description

Deserialization of untrusted data in python in pyfory versions 0.12.0 through 0.12.2, or the legacy pyfury versions from 0.1.0 through 0.10.3: allows arbitrary code execution. An application is vulnerable if it reads pyfory serialized data from untrusted sources. An attacker can craft a data stream that selects pickle-fallback serializer during deserialization, leading to the execution of `pickle.loads`, which is vulnerable to remote code execution.

Users are recommended to upgrade to pyfory version 0.12.3 or later, which has removed pickle fallback serializer and thus fixes this issue.
