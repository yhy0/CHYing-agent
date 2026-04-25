# Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability

**GHSA**: GHSA-5j33-cvvr-w245 | **CVE**: CVE-2024-50379 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-367

**Affected Packages**:
- **org.apache.tomcat:tomcat-catalina** (maven): >= 11.0.0-M1, < 11.0.2
- **org.apache.tomcat:tomcat-catalina** (maven): >= 10.1.0-M1, < 10.1.34
- **org.apache.tomcat:tomcat-catalina** (maven): >= 9.0.0.M1, < 9.0.98
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 11.0.0-M1, < 11.0.2
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 10.1.0-M1, < 10.1.34
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 9.0.0.M1, < 9.0.98
- **org.apache.tomcat:tomcat-catalina** (maven): >= 8.5.0, <= 8.5.100
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 8.5.0, <= 8.5.100

## Description

Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation in Apache Tomcat permits an RCE on case insensitive file systems when the default servlet is enabled for write (non-default configuration).

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.0.97. The following versions were EOL at the time the CVE was created but are known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions may also be affected.

Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.
