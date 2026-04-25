# H2O.ai H2O vulnerable to deserialization attacks via a JDBC Connection URL

**GHSA**: GHSA-hrmc-jmp7-mpm2 | **CVE**: CVE-2024-45758 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-502

**Affected Packages**:
- **ai.h2o:h2o-core** (maven): <= 3.46.0.7
- **h2o** (pip): <= 3.46.0.7

## Description

H2O.ai H2O through 3.46.0.4 allows attackers to arbitrarily set the JDBC URL, leading to deserialization attacks, file reads, and command execution. Exploitation can occur when an attacker has access to post to the ImportSQLTable URI with a JSON document containing a connection_url property with any typical JDBC Connection URL attack payload such as one that uses queryInterceptors.
