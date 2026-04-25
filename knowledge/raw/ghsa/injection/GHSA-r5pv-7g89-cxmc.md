# SQL injection in audit endpoint

**GHSA**: GHSA-r5pv-7g89-cxmc | **CVE**: CVE-2023-35088 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **org.apache.inlong:manager-service** (maven): >= 1.4.0, < 1.8.0

## Description

Improper Neutralization of Special Elements Used in an SQL Command ('SQL Injection') vulnerability in Apache Software Foundation Apache InLong.This issue affects Apache InLong: from 1.4.0 through 1.7.0. 
In the toAuditCkSql method, the groupId, streamId, auditId, and dt are directly concatenated into the SQL query statement, which may lead to SQL injection attacks.
Users are advised to upgrade to Apache InLong's 1.8.0 or cherry-pick [1] to solve it.

[1]  https://github.com/apache/inlong/pull/8198
