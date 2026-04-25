# Apache James server: Privilege escalation via JMX pre-authentication deserialization

**GHSA**: GHSA-px7w-c9gw-7gj3 | **CVE**: CVE-2023-51518 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.james:james-server** (maven): <= 3.7.4
- **org.apache.james:james-server** (maven): >= 3.8.0, < 3.8.1

## Description

Apache James prior to version 3.7.5 and 3.8.0 exposes a JMX endpoint on localhost subject to pre-authentication deserialisation of untrusted data.
Given a deserialisation gadjet, this could be leveraged as part of an exploit chain that could result in privilege escalation.
Note that by default JMX endpoint is only bound locally.

We recommend users to:
 - Upgrade to a non-vulnerable Apache James version

 - Run Apache James isolated from other processes (docker - dedicated virtual machine)
 - If possible turn off JMX


