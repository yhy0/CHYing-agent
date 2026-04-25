# Apache Spark UI vulnerable to Command Injection

**GHSA**: GHSA-59hw-j9g6-mfg3 | **CVE**: CVE-2023-32007 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-77

**Affected Packages**:
- **org.apache.spark:spark-parent_2.12** (maven): >= 3.1.1, < 3.2.2
- **pyspark** (pip): >= 3.1.1, < 3.2.2

## Description

The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This issue was disclosed earlier as CVE-2022-33891, but incorrectly claimed version 3.1.3 (which has since gone EOL) would not be affected.

NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

Users are recommended to upgrade to a supported version of Apache Spark, such as version 3.4.0.
