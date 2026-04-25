# Brokercap Bifrost subject to authentication bypass when using HTTP basic authentication

**GHSA**: GHSA-p6fh-xc6r-g5hw | **CVE**: CVE-2022-39219 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-287, CWE-732

**Affected Packages**:
- **github.com/brokercap/Bifrost** (go): <= 1.8.6-release

## Description

Bifrost is a middleware package which can synchronize MySQL/MariaDB binlog data to other types of databases. Versions 1.8.6-release and prior are vulnerable to authentication bypass when using HTTP basic authentication. This may allow group members who only have read permissions to write requests when they are normally forbidden from doing so. Version 1.8.7-release contains a patch. There are currently no known workarounds.

