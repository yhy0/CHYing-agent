# MySQL Connectors takeover vulnerability

**GHSA**: GHSA-m6vm-37g8-gqvh | **CVE**: CVE-2023-22102 | **Severity**: high (CVSS 8.4)

**CWE**: N/A

**Affected Packages**:
- **com.mysql:mysql-connector-j** (maven): < 8.2.0
- **mysql:mysql-connector-java** (maven): <= 8.0.33

## Description

Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that are affected are 8.1.0 and prior. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in MySQL Connectors, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in takeover of MySQL Connectors.
