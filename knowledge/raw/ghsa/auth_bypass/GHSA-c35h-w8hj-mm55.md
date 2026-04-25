# Apache Pulsar: Improper Authentication for Pulsar Proxy Statistics Endpoint

**GHSA**: GHSA-c35h-w8hj-mm55 | **CVE**: CVE-2022-34321 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-306

**Affected Packages**:
- **org.apache.pulsar:pulsar-proxy** (maven): >= 2.6.0, <= 2.10.5
- **org.apache.pulsar:pulsar-proxy** (maven): >= 2.11.0, <= 2.11.2
- **org.apache.pulsar:pulsar-proxy** (maven): >= 3.0.0, <= 3.0.1
- **org.apache.pulsar:pulsar-proxy** (maven): >= 3.1.0, < 3.1.1

## Description

Improper Authentication vulnerability in Apache Pulsar Proxy allows an attacker to connect to the /proxy-stats endpoint without authentication. The vulnerable endpoint exposes detailed statistics about live connections, along with the capability to modify the logging level of proxied connections without requiring proper authentication credentials.

This issue affects Apache Pulsar versions from 2.6.0 to 2.10.5, from 2.11.0 to 2.11.2, from 3.0.0 to 3.0.1, and 3.1.0.

The known risks include exposing sensitive information such as connected client IP and unauthorized logging level manipulation which could lead to a denial-of-service condition by significantly increasing the proxy's logging overhead. When deployed via the Apache Pulsar Helm chart within Kubernetes environments, the actual client IP might not be revealed through the load balancer's default behavior, which typically obscures the original source IP addresses when externalTrafficPolicy is being configured to "Cluster" by default. The /proxy-stats endpoint contains topic level statistics, however, in the default configuration, the topic level statistics aren't known to be exposed.

2.10 Pulsar Proxy users should upgrade to at least 2.10.6.
2.11 Pulsar Proxy users should upgrade to at least 2.11.3.
3.0 Pulsar Proxy users should upgrade to at least 3.0.2.
3.1 Pulsar Proxy users should upgrade to at least 3.1.1.

Users operating versions prior to those listed above should upgrade to the aforementioned patched versions or newer versions. Additionally, it's imperative to recognize that the Apache Pulsar Proxy is not intended for direct exposure to the internet. The architectural design of Pulsar Proxy assumes that it will operate within a secured network environment, safeguarded by appropriate perimeter defenses.
