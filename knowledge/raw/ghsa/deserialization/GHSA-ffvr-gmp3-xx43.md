# Apache EventMesh: raft Hessian Deserialization Vulnerability allowing remote code execution

**GHSA**: GHSA-ffvr-gmp3-xx43 | **CVE**: CVE-2024-56180 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.eventmesh:eventmesh-meta-raft** (maven): >= 1.10.1, < 1.11.0

## Description

CWE-502 Deserialization of Untrusted Data at the eventmesh-meta-raft plugin module in Apache EventMesh master branch without release version on windows\linux\mac os e.g. platforms allows attackers to send controlled message and remote code execute via hessian deserialization rpc protocol. Users can use the code under the master branch in project repo or version 1.11.0 to fix this issue.
