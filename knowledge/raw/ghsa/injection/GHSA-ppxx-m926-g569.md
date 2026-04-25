# Apache Kylin vulnerable to remote code execution

**GHSA**: GHSA-ppxx-m926-g569 | **CVE**: CVE-2022-24697 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-77, CWE-78

**Affected Packages**:
- **org.apache.kylin:kylin-core-common** (maven): < 4.0.2
- **org.apache.kylin:kylin-spark-project** (maven): < 4.0.2
- **org.apache.kylin:kylin-server-base** (maven): < 4.0.2

## Description

Kylin's cube designer function has a command injection vulnerability when overwriting system parameters in the configuration overwrites menu. RCE can be implemented by closing the single quotation marks around the parameter value of “-- conf=” to inject any operating system command into the command line parameters. This vulnerability affects Kylin 2 version 2.6.5 and earlier, Kylin 3 version 3.1.2 and earlier, and Kylin 4 version 4.0.1 and earlier.
