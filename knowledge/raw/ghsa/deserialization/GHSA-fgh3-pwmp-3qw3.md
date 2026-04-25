# Apache Inlong Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-fgh3-pwmp-3qw3 | **CVE**: CVE-2024-26579 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.inlong:manager-pojo** (maven): >= 1.7.0, < 1.12.0

## Description

Deserialization of Untrusted Data vulnerability in Apache InLong. This issue affects Apache InLong: from 1.7.0 through 1.11.0. The attackers can bypass using malicious parameters.

Users are advised to upgrade to Apache InLong's 1.12.0 or cherry-pick [1], [2] to solve it.

[1]  https://github.com/apache/inlong/pull/9694 

[2]  https://github.com/apache/inlong/pull/9707
