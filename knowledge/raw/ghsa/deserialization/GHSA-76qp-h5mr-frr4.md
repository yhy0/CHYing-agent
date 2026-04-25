# Apache Kafka Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-76qp-h5mr-frr4 | **CVE**: CVE-2025-27818 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.kafka:kafka_2.11** (maven): >= 2.3.0, <= 2.4.1
- **org.apache.kafka:kafka_2.12** (maven): >= 2.3.0, < 3.9.1
- **org.apache.kafka:kafka_2.13** (maven): >= 2.4.0, < 3.9.1

## Description

A possible security vulnerability has been identified in Apache Kafka.
This requires access to a alterConfig to the cluster resource, or Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config
and a SASL-based security protocol, which has been possible on Kafka clusters since Apache Kafka 2.0.0 (Kafka Connect 2.3.0).
When configuring the broker via config file or AlterConfig command, or connector via the Kafka Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config`
property for any of the connector's Kafka clients to "com.sun.security.auth.module.LdapLoginModule", which can be done via the
`producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties.
This will allow the server to connect to the attacker's LDAP server
and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server.
Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath.

Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box
configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector
client override policy that permits them.

Since Apache Kafka 3.9.1/4.0.0, we have added a system property ("-Dorg.apache.kafka.disallowed.login.modules") to disable the problematic login modules usage
in SASL JAAS configuration. Also by default "com.sun.security.auth.module.JndiLoginModule,com.sun.security.auth.module.LdapLoginModule" are disabled in Apache Kafka Connect 3.9.1/4.0.0. 

We advise the Kafka users to validate connector configurations and only allow trusted LDAP configurations. Also examine connector dependencies for 
vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally,
in addition to leveraging the "org.apache.kafka.disallowed.login.modules" system property, Kafka Connect users can also implement their own connector
client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.
