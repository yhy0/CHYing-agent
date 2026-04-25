# Apache Linkis DataSource's JDBC Datasource Module with DB2 has JNDI Injection vulnerability

**GHSA**: GHSA-7qpc-4xx9-x5qw | **CVE**: CVE-2023-49566 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.linkis:linkis-datasource** (maven): < 1.6.0

## Description

In Apache Linkis <=1.5.0, due to the lack of effective filteringof parameters, an attacker configuring malicious `db2` parameters in the DataSource Manager Module will result in jndi injection. Therefore, the parameters in the DB2 URL should be blacklisted. 

This attack requires the attacker to obtain an authorized account from Linkis before it can be carried out.

Versions of Apache Linkis <=1.5.0 will be affected. We recommend users upgrade the version of Linkis to version 1.6.0.
