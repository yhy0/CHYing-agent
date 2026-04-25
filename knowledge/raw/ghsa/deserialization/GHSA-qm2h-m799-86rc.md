# Apache Linkis JDBC EngineConn has deserialization vulnerability

**GHSA**: GHSA-qm2h-m799-86rc | **CVE**: CVE-2023-29215 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.linkis:linkis-engineconn** (maven): < 1.3.2

## Description

In Apache Linkis <=1.3.1, due to the lack of effective filtering of parameters, an attacker configuring malicious Mysql JDBC parameters in JDBC EngineConn Module will trigger a deserialization vulnerability and eventually lead to remote code execution. Therefore, the parameters in the Mysql JDBC URL should be blacklisted. Users should upgrade their version of Linkis to version 1.3.2.
