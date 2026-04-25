# Apache Tomcat - Authentication Bypass

**GHSA**: GHSA-xcpr-7mr4-h4xq | **CVE**: CVE-2024-52316 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-391, CWE-754

**Affected Packages**:
- **org.apache.tomcat:tomcat-catalina** (maven): < 9.0.96
- **org.apache.tomcat:tomcat-catalina** (maven): >= 10.1.0-M1, < 10.1.30
- **org.apache.tomcat:tomcat-catalina** (maven): >= 11.0.0-M1, <= 11.0.0-M26

## Description

Unchecked Error Condition vulnerability in Apache Tomcat. If Tomcat is configured to use a custom Jakarta Authentication (formerly JASPIC) ServerAuthContext component which may throw an exception during the authentication process without explicitly setting an HTTP status to indicate failure, the authentication may not fail, allowing the user to bypass the authentication process. There are no known Jakarta Authentication components that behave in this way.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M26, from 10.1.0-M1 through 10.1.30, from 9.0.0-M1 through 9.0.95. The following versions were EOL at the time the CVE was created but are known to be affected: 8.5.0 though 8.5.100.

Users are recommended to upgrade to version 11.0.0, 10.1.31 or 9.0.96, which fix the issue.
