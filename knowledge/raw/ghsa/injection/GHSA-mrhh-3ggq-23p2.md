# Horovod Vulnerable to Command Injection

**GHSA**: GHSA-mrhh-3ggq-23p2 | **CVE**: CVE-2024-10190 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-77, CWE-502

**Affected Packages**:
- **horovod** (pip): <= 0.28.1

## Description

Horovod versions up to and including v0.28.1 are vulnerable to unauthenticated remote code execution. The vulnerability is due to improper handling of base64-encoded data in the `ElasticRendezvousHandler`, a subclass of `KVStoreHandler`. Specifically, the `_put_value` method in `ElasticRendezvousHandler` calls `codec.loads_base64(value)`, which eventually invokes `cloudpickle.loads(decoded)`. This allows an attacker to send a malicious pickle object via a PUT request, leading to arbitrary code execution on the server.
