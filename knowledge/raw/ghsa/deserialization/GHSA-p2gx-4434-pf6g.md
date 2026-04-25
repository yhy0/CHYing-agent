# Apache InLong: Logged-in user could exploit an arbitrary file read vulnerability

**GHSA**: GHSA-p2gx-4434-pf6g | **CVE**: CVE-2024-26580 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.inlong:manager-common** (maven): >= 1.8.0, < 1.11.0

## Description

Deserialization of Untrusted Data vulnerability in Apache InLong.This issue affects Apache InLong: from 1.8.0 through 1.10.0, the attackers can 

use the specific payload to read from an arbitrary file. Users are advised to upgrade to Apache InLong's 1.11.0 or cherry-pick [1] to solve it.

[1]  https://github.com/apache/inlong/pull/9673
