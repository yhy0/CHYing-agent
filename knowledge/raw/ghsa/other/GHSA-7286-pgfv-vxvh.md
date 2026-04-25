# Authorization Bypass Through User-Controlled Key vulnerability in Apache ZooKeeper

**GHSA**: GHSA-7286-pgfv-vxvh | **CVE**: CVE-2023-44981 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-639

**Affected Packages**:
- **org.apache.zookeeper:zookeeper** (maven): < 3.7.2
- **org.apache.zookeeper:zookeeper** (maven): >= 3.8.0, < 3.8.3
- **org.apache.zookeeper:zookeeper** (maven): >= 3.9.0, < 3.9.1

## Description

Authorization Bypass Through User-Controlled Key vulnerability in Apache ZooKeeper. If SASL Quorum Peer authentication is enabled in ZooKeeper (quorum.auth.enableSasl=true), the authorization is done by verifying that the instance part in SASL authentication ID is listed in zoo.cfg server list. The instance part in SASL auth ID is optional and if it's missing, like 'eve@EXAMPLE.COM', the authorization check will be skipped. As a result an arbitrary endpoint could join the cluster and begin propagating counterfeit changes to the leader, essentially giving it complete read-write access to the data tree. Quorum Peer authentication is not enabled by default.

Users are recommended to upgrade to version 3.9.1, 3.8.3, 3.7.2, which fixes the issue.

Alternately ensure the ensemble election/quorum communication is protected by a firewall as this will mitigate the issue.

See the documentation for more details on correct cluster administration.
