# Apache Ignite: Possible RCE when deserializing incoming messages by the server node

**GHSA**: GHSA-8355-xj3p-hv6q | **CVE**: CVE-2024-52577 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.ignite:ignite-core** (maven): >= 2.6.0, < 2.17.0

## Description

In Apache Ignite versions from 2.6.0 and before 2.17.0, configured Class Serialization Filters are ignored for some Ignite endpoints. The vulnerability could be exploited if an attacker manually crafts an Ignite message containing a vulnerable object whose class is present in the Ignite server classpath and sends it to Ignite server endpoints. Deserialization of such a message by the Ignite server may result in the execution of arbitrary code on the Apache Ignite server side.
