# lollms vulnerable to path traversal due to unauthenticated root folder settings change

**GHSA**: GHSA-9chm-m6x2-6fvc | **CVE**: CVE-2024-6085 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-22

**Affected Packages**:
- **lollms** (pip): <= 9.5.1

## Description

A path traversal vulnerability exists in the XTTS server included in the lollms package, version v9.6. This vulnerability arises from the ability to perform an unauthenticated root folder settings change. Although the read file endpoint is protected against path traversals, this protection can be bypassed by changing the root folder to '/'. This allows attackers to read arbitrary files on the system. Additionally, the output folders can be changed to write arbitrary audio files to any location on the system.
