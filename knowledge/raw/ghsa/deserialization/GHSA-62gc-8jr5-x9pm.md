# Apache InLong Deserialization of Untrusted Data Vulnerability

**GHSA**: GHSA-62gc-8jr5-x9pm | **CVE**: CVE-2025-27531 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.inlong:inlong-manager** (maven): >= 1.13.0, < 2.1.0

## Description

Deserialization of Untrusted Data vulnerability in Apache InLong. This issue affects Apache InLong: from 1.13.0 before 2.1.0, this issue would allow an authenticated attacker to read arbitrary files by double writing the param. Users are recommended to upgrade to version 2.1.0, which fixes the issue.
