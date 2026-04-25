# Apache InLong Improper Privilege Management vulnerability

**GHSA**: GHSA-q5p5-xg93-2jqc | **CVE**: CVE-2023-31062 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-269

**Affected Packages**:
- **org.apache.inlong:manager-pojo** (maven): >= 1.2.0, < 1.7.0
- **org.apache.inlong:manager-dao** (maven): >= 1.2.0, < 1.7.0
- **org.apache.inlong:manager-service** (maven): >= 1.2.0, < 1.7.0
- **org.apache.inlong:manager-web** (maven): >= 1.2.0, < 1.7.0

## Description

Improper Privilege Management Vulnerabilities in Apache Software Foundation Apache InLong.This issue affects Apache InLong: from 1.2.0 through 1.6.0.  When the attacker has access to a valid (but unprivileged) account, the exploit can be executed using Burp Suite by sending a login request and following it with a subsequent HTTP request using the returned cookie.

Users are advised to upgrade to Apache InLong's 1.7.0 or cherry-pick https://github.com/apache/inlong/pull/7836 to solve it.





