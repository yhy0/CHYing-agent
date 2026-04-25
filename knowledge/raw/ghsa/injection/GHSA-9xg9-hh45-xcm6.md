# Apache InLong Manager Remote Code Execution vulnerability

**GHSA**: GHSA-9xg9-hh45-xcm6 | **CVE**: CVE-2023-51784 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.apache.inlong:manager-pojo** (maven): >= 1.5.0, < 1.10.0

## Description

Improper Control of Generation of Code ('Code Injection') vulnerability in Apache InLong.This issue affects Apache InLong: from 1.5.0 through 1.9.0, which could lead to Remote Code Execution. Users are advised to upgrade to Apache InLong's 1.10.0 or cherry-pick [1] to solve it.

[1]  https://github.com/apache/inlong/pull/9329
