# Apache Linkis DatasourceManager module has deserialization vulnerability

**GHSA**: GHSA-rrhf-32rq-f28h | **CVE**: CVE-2023-29216 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.linkis:linkis-datasource** (maven): < 1.3.2

## Description

In Apache Linkis <=1.3.1, because the parameters are not effectively filtered, the attacker can use the MySQL data source and malicious parameters to configure a new data source to trigger a deserialization vulnerability, eventually leading to remote code execution. Users should upgrade their version of Linkis to version 1.3.2.
