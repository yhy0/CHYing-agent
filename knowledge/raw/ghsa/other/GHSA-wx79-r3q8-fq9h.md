# Apache InLong has Files or Directories Accessible to External Parties in Apache InLong

**GHSA**: GHSA-wx79-r3q8-fq9h | **CVE**: CVE-2023-31066 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-552

**Affected Packages**:
- **org.apache.inlong:manager-service** (maven): >= 1.4.0, < 1.7.0
- **org.apache.inlong:manager-web** (maven): >= 1.4.0, < 1.7.0

## Description

Files or Directories Accessible to External Parties vulnerability in Apache Software Foundation Apache InLong. This issue affects Apache InLong: from 1.4.0 through 1.6.0. Different users in InLong could delete, edit, stop, and start others' sources. Users are advised to upgrade to Apache InLong's 1.7.0 or cherry-pick https://github.com/apache/inlong/pull/7775 to solve it.



