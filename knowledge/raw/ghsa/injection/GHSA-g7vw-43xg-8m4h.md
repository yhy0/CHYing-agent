# SQL injection in Liferay Portal

**GHSA**: GHSA-g7vw-43xg-8m4h | **CVE**: CVE-2023-33945 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-89

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.3.1, < 7.4.3.18

## Description

SQL injection vulnerability in the upgrade process for SQL Server in Liferay Portal 7.3.1 through 7.4.3.17, and Liferay DXP 7.3 before update 6, and 7.4 before update 18 allows attackers to execute arbitrary SQL commands via the name of a database table's primary key index. This vulnerability is only exploitable when chained with other attacks. To exploit this vulnerability, the attacker must modify the database and wait for the application to be upgraded.
