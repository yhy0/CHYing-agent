# Authorization Bypass in Apache InLong

**GHSA**: GHSA-rp6x-ggw6-8g56 | **CVE**: CVE-2023-43668 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502, CWE-639

**Affected Packages**:
- **org.apache.inlong:manager-pojo** (maven): >= 1.4.0, < 1.9.0

## Description

Authorization Bypass Through User-Controlled Key vulnerability in Apache InLong.This issue affects Apache InLong: from 1.4.0 through 1.8.0, 

some sensitive params  checks will be bypassed, like "autoDeserizalize","allowLoadLocalInfile"....

.  

Users are advised to upgrade to Apache InLong's 1.9.0 or cherry-pick [1] to solve it.

[1]  https://github.com/apache/inlong/pull/8604 


