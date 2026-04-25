# Apache Kafka Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-mcwh-c9pg-xw43 | **CVE**: CVE-2025-27819 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.kafka:kafka_2.10** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.11** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.12** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.13** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.8.0** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.8.2** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.9.1** (maven): < 3.4.0
- **org.apache.kafka:kafka_2.9.2** (maven): < 3.4.0

## Description

In CVE-2023-25194, we announced the RCE/Denial of service attack via SASL JAAS JndiLoginModule configuration in Kafka Connect API. But not only Kafka Connect API is vulnerable to this attack, the Apache Kafka brokers also have this vulnerability. To exploit this vulnerability, the attacker needs to be able to connect to the Kafka cluster and have the AlterConfigs permission on the cluster resource.


Since Apache Kafka 3.4.0, we have added a system property ("-Dorg.apache.kafka.disallowed.login.modules") to disable the problematic login modules usage in SASL JAAS configuration. Also by default "com.sun.security.auth.module.JndiLoginModule" is disabled in Apache Kafka 3.4.0, and "com.sun.security.auth.module.JndiLoginModule,com.sun.security.auth.module.LdapLoginModule" is disabled by default in in Apache Kafka 3.9.1/4.0.0
