# Apache Tomcat Allocation of Resources Without Limits or Throttling vulnerability

**GHSA**: GHSA-7jqf-v358-p8g7 | **CVE**: CVE-2024-38286 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-770

**Affected Packages**:
- **org.apache.tomcat:tomcat-util** (maven): >= 11.0.0-M1, < 11.0.0-M21
- **org.apache.tomcat:tomcat-util** (maven): >= 10.1.0-M1, < 10.1.25
- **org.apache.tomcat:tomcat-util** (maven): >= 9.0.13, < 9.0.90
- **org.apache.tomcat:tomcat-util** (maven): >= 8.5.35, <= 8.5.100
- **org.apache.tomcat:tomcat-util** (maven): >= 7.0.92, <= 7.0.109

## Description

Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M20, from 10.1.0-M1 through 10.1.24, from 9.0.13 through 9.0.89. The following versions were EOL at the time the CVE was created but are known to be affected: 8.5.35 through 8.5.100 and 7.0.92 through 7.0.109.

Users are recommended to upgrade to version 11.0.0-M21, 10.1.25, or 9.0.90, which fixes the issue.

Apache Tomcat, under certain configurations on any platform, allows an attacker to cause an OutOfMemoryError by abusing the TLS handshake process.
