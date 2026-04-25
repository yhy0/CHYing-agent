# Apache ActiveMQ is vulnerable to Remote Code Execution

**GHSA**: GHSA-crg9-44h2-xw35 | **CVE**: CVE-2023-46604 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.activemq:activemq-client** (maven): < 5.15.16
- **org.apache.activemq:activemq-client** (maven): >= 5.16.0, < 5.16.7
- **org.apache.activemq:activemq-client** (maven): >= 5.17.0, < 5.17.6
- **org.apache.activemq:activemq-client** (maven): >= 5.18.0, < 5.18.3
- **org.apache.activemq:activemq-openwire-legacy** (maven): >= 5.8.0, < 5.15.16
- **org.apache.activemq:activemq-openwire-legacy** (maven): >= 5.16.0, < 5.16.7
- **org.apache.activemq:activemq-openwire-legacy** (maven): >= 5.17.0, < 5.17.6
- **org.apache.activemq:activemq-openwire-legacy** (maven): >= 5.18.0, < 5.18.3

## Description

Apache ActiveMQ is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker with network access to a broker to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause the broker to instantiate any class on the classpath. 

Users are recommended to upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3, which fixes this issue.
