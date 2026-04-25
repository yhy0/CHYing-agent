# Apache RocketMQ may have remote code execution vulnerability when using update configuration function

**GHSA**: GHSA-x3cq-8f32-5f63 | **CVE**: CVE-2023-33246 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.apache.rocketmq:rocketmq-broker** (maven): >= 5.0.0, < 5.1.1
- **org.apache.rocketmq:rocketmq-namesrv** (maven): >= 4.0.0, < 4.9.6
- **org.apache.rocketmq:rocketmq-controller** (maven): >= 5.0.0, < 5.1.1
- **org.apache.rocketmq:rocketmq-namesrv** (maven): >= 5.0.0, < 5.1.1

## Description

For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. 

Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. 

To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .
