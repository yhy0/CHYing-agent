# Withdrawn Advisory: Dask Vulnerable to Command Injection

**GHSA**: GHSA-xqgj-r6xv-9cw4 | **CVE**: CVE-2024-10096 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-77

**Affected Packages**:
- **dask** (pip): <= 2024.8.2

## Description

# Withdrawn Advisory
This advisory has been withdrawn because it describes [intended functionality](https://distributed.dask.org/en/stable/limitations.html?highlight=host#security). This link is maintained to preserve external references.

# Original Description

Dask versions <=2024.8.2 contain a vulnerability in the Dask Distributed Server where the use of pickle serialization allows attackers to craft malicious objects. These objects can be serialized on the client side and sent to the server for deserialization, leading to remote command execution and potentially granting full control over the Dask server.
