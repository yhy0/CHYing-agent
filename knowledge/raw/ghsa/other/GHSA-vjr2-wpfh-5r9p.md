# Apache Ranger Hive Plugin missing permissions check

**GHSA**: GHSA-vjr2-wpfh-5r9p | **CVE**: CVE-2021-40331 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-732

**Affected Packages**:
- **org.apache.ranger:ranger-hive-plugin** (maven): >= 2.0.0, < 2.4.0

## Description

An Incorrect Permission Assignment for Critical Resource vulnerability was found in the Apache Ranger Hive Plugin. Any user with SELECT privilege on a database can alter the ownership of the table in Hive when Apache Ranger Hive Plugin is enabled
This issue affects Apache Ranger Hive Plugin: from 2.0.0 through 2.3.0. Users are recommended to upgrade to version 2.4.0 or later.



