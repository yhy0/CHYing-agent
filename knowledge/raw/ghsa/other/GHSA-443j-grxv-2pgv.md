# Apache ActiveMQ Artemis: Authenticated users could perform RCE via Jolokia MBeans

**GHSA**: GHSA-443j-grxv-2pgv | **CVE**: CVE-2023-50780 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-285

**Affected Packages**:
- **org.apache.activemq:artemis-cli** (maven): < 2.29.0

## Description

Apache ActiveMQ Artemis allows access to diagnostic information and controls through MBeans, which are also exposed through the authenticated Jolokia endpoint. Before version 2.29.0, this also included the Log4J2 MBean. This MBean is not meant for exposure to non-administrative users. This could eventually allow an authenticated attacker to write arbitrary files to the filesystem and indirectly achieve RCE.


Users are recommended to upgrade to version 2.29.0 or later, which fixes the issue.
