# H2O Deserialization of Untrusted Data Vulnerability

**GHSA**: GHSA-h7xg-cmpp-48hf | **CVE**: CVE-2024-10553 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **h2o** (pip): < 3.46.0.6
- **ai.h2o:h2o-core** (maven): < 3.46.0.6

## Description

A vulnerability in the h2oai/h2o-3 REST API versions 3.46.0.4 allows unauthenticated remote attackers to execute arbitrary code via deserialization of untrusted data. The vulnerability exists in the endpoints POST /99/ImportSQLTable and POST /3/SaveToHiveTable, where user-controlled JDBC URLs are passed to DriverManager.getConnection, leading to deserialization if a MySQL or PostgreSQL driver is available in the classpath. This issue is fixed in version 3.46.0.6.
