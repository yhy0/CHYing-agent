# Amazon JDBC Driver for Redshift SQL Injection via line comment generation

**GHSA**: GHSA-x3wm-hffr-chwm | **CVE**: CVE-2024-32888 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-89

**Affected Packages**:
- **com.amazon.redshift:redshift-jdbc42** (maven): < 2.1.0.28

## Description

### Impact

SQL injection is possible when using the non-default connection property `preferQueryMode=simple` in combination with application code which has a vulnerable SQL that negates a parameter value.

There is no vulnerability in the driver when using the default, extended query mode. Note that `preferQueryMode` is not a supported parameter in Redshift JDBC driver, and is inherited code from Postgres JDBC driver. Users who do not override default settings to utilize this unsupported query mode are not affected.

### Patch

This issue is patched in driver version 2.1.0.28.

### Workarounds

Do not use the connection property `preferQueryMode=simple`. (NOTE: If you do not explicitly specify a query mode, then you are using the default of extended query mode and are not affected by this issue.)

### References

Similar to finding in Postgres JDBC: https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56

If you have any questions or comments about this advisory, we ask that you contact AWS Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting) or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.
