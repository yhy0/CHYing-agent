# Apache Pulsar Broker's Rest Producer vulnerable to Incorrect Authorization

**GHSA**: GHSA-j2r7-3rvw-g7gx | **CVE**: CVE-2023-30428 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-863

**Affected Packages**:
- **org.apache.pulsar:pulsar-broker** (maven): >= 2.9.0, < 2.10.4
- **org.apache.pulsar:pulsar-broker** (maven): = 2.11.0

## Description

Incorrect Authorization vulnerability in Apache Software Foundation Apache Pulsar Broker's Rest Producer allows authenticated user with a custom HTTP header to produce a message to any topic using the broker's admin role.
This issue affects Apache Pulsar Brokers: from 2.9.0 through 2.9.5, from 2.10.0 before 2.10.4, 2.11.0.

The vulnerability is exploitable when an attacker can connect directly to the Pulsar Broker. If an attacker is connecting through the Pulsar Proxy, there is no known way to exploit this authorization vulnerability.

There are two known risks for affected users. First, an attacker could produce garbage messages to any topic in the cluster. Second, an attacker could produce messages to the topic level policies topic for other tenants and influence topic settings that could lead to exfiltration and/or deletion of messages for other tenants.

2.8 Pulsar Broker users and earlier are unaffected.
2.9 Pulsar Broker users should upgrade to one of the patched versions.
2.10 Pulsar Broker users should upgrade to at least 2.10.4.
2.11 Pulsar Broker users should upgrade to at least 2.11.1.
3.0 Pulsar Broker users are unaffected.


