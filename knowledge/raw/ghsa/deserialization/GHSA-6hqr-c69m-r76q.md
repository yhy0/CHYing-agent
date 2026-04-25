# Apache Hive: Deserialization of untrusted data when fetching partitions from the Metastore

**GHSA**: GHSA-6hqr-c69m-r76q | **CVE**: CVE-2022-41137 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.hive:hive-exec** (maven): = 4.0.0-alpha-1

## Description

Apache Hive Metastore (HMS) uses SerializationUtilities#deserializeObjectWithTypeInformation method when filtering and fetching partitions that is unsafe and can lead to Remote Code Execution (RCE) since it allows the deserialization of arbitrary data.

In real deployments, the vulnerability can be exploited only by authenticated users/clients that were able to successfully establish a connection to the Metastore. From an API perspective any code that calls the unsafe method may be vulnerable unless it performs additional prerechecks on the input arguments.
