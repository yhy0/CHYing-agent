# Apache Continuum vulnerable to Command Injection through Installations REST API

**GHSA**: GHSA-77p9-w6pj-rmvg | **CVE**: CVE-2016-15057 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-77

**Affected Packages**:
- **org.apache.continuum:continuum** (maven): <= 1.4.2

## Description

***UNSUPPORTED WHEN ASSIGNED*** 

Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in Apache Continuum.

This issue affects Apache Continuum: all versions.

Attackers with access to the Installations REST API can use this to invoke arbitrary commands on the server.

As this project is retired, we do not plan to release a version that fixes this issue. Users are recommended to find an alternative or restrict access to the instance to trusted users.

NOTE: This vulnerability only affects products that are no longer supported by the maintainer.
