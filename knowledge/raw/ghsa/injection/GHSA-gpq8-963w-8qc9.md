# RocketMQ NameServer component Code Injection vulnerability

**GHSA**: GHSA-gpq8-963w-8qc9 | **CVE**: CVE-2023-37582 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.apache.rocketmq:rocketmq-namesrv** (maven): < 4.9.7
- **org.apache.rocketmq:rocketmq-namesrv** (maven): >= 5.0.0, < 5.1.2

## Description

The RocketMQ NameServer component still has a remote command execution vulnerability as the CVE-2023-33246 issue was not completely fixed in version 5.1.1. 

When NameServer address are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function on the NameServer component to execute commands as the system users that RocketMQ is running as. 

It is recommended for users to upgrade their NameServer version to 5.1.2 or above for RocketMQ 5.x or 4.9.7 or above for RocketMQ 4.x to prevent these attacks.
