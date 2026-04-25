# XXL-RPC Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-f984-3wx8-grp9 | **CVE**: CVE-2023-45146 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-502

**Affected Packages**:
- **com.xuxueli:xxl-rpc-core** (maven): <= 1.7.0

## Description

XXL-RPC is a high performance, distributed RPC framework. With it, a TCP server can be set up using the Netty framework and the Hessian serialization mechanism. When such a configuration is used, attackers may be able to connect to the server and provide malicious serialized objects that, once deserialized, force it to execute arbitrary code. This can be abused to take control of the machine the server is running by way of remote code execution. This issue has not been fixed.
