# Apache Pulsar: Improper Input Validation in Pulsar Function Worker allows Remote Code Execution

**GHSA**: GHSA-xp2r-g8qq-44hh | **CVE**: CVE-2024-27135 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-20

**Affected Packages**:
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 2.4.0, <= 2.10.5
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 2.11.0, <= 2.11.3
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.0.0, <= 3.0.2
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.1.0, <= 3.1.2
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.2.0, < 3.2.1

## Description

Improper input validation in the Pulsar Function Worker allows a malicious authenticated user to execute arbitrary Java code on the Pulsar Function worker, outside of the sandboxes designated for running user-provided functions. This vulnerability also applies to the Pulsar Broker when it is configured with "functionsWorkerEnabled=true".

This issue affects Apache Pulsar versions from 2.4.0 to 2.10.5, from 2.11.0 to 2.11.3, from 3.0.0 to 3.0.2, from 3.1.0 to 3.1.2, and 3.2.0. 

2.10 Pulsar Function Worker users should upgrade to at least 2.10.6.
2.11 Pulsar Function Worker users should upgrade to at least 2.11.4.
3.0 Pulsar Function Worker users should upgrade to at least 3.0.3.
3.1 Pulsar Function Worker users should upgrade to at least 3.1.3.
3.2 Pulsar Function Worker users should upgrade to at least 3.2.1.

Users operating versions prior to those listed above should upgrade to the aforementioned patched versions or newer versions.
