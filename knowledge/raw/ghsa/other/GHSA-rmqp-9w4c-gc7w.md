# Apache Axis 1.x (EOL) may allow RCE when untrusted input is passed to getService

**GHSA**: GHSA-rmqp-9w4c-gc7w | **CVE**: CVE-2023-40743 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-20, CWE-75

**Affected Packages**:
- **org.apache.axis:axis** (maven): <= 1.4
- **axis:axis** (maven): <= 1.4

## Description

When integrating Apache Axis 1.x in an application, it may not have been obvious that looking up a service through "ServiceFactory.getService" allows potentially dangerous lookup mechanisms such as LDAP. When passing untrusted input to this API method, this could expose the application to DoS, SSRF and even attacks leading to RCE.

As Axis 1 has been EOL we recommend you migrate to a different SOAP engine, such as Apache Axis 2/Java. As a workaround, you may review your code to verify no untrusted or unsanitized input is passed to "ServiceFactory.getService", or by applying the patch from  https://github.com/apache/axis-axis1-java/commit/7e66753427466590d6def0125e448d2791723210 . The Apache Axis project does not expect to create an Axis 1.x release fixing this problem, though contributors that would like to work towards this are welcome.
