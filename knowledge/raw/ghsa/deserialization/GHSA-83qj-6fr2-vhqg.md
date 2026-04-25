# Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT

**GHSA**: GHSA-83qj-6fr2-vhqg | **CVE**: CVE-2025-24813 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-44, CWE-502

**Affected Packages**:
- **org.apache.tomcat:tomcat-catalina** (maven): >= 11.0.0-M1, < 11.0.3
- **org.apache.tomcat:tomcat-catalina** (maven): >= 10.1.0-M1, < 10.1.35
- **org.apache.tomcat:tomcat-catalina** (maven): >= 9.0.0.M1, < 9.0.99
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 11.0.0-M1, < 11.0.3
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 10.1.0-M1, < 10.1.35
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 9.0.0.M1, < 9.0.99
- **org.apache.tomcat:tomcat-catalina** (maven): >= 8.5.0, <= 8.5.100
- **org.apache.tomcat.embed:tomcat-embed-core** (maven): >= 8.5.0, <= 8.5.100

## Description

Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 10.1.0-M1 through 10.1.34, from 9.0.0.M1 through 9.0.98. The following versions were EOL at the time the CVE was created but are known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions may also be affected.

If all of the following were true, a malicious user was able to view security sensitive files and/or inject content into those files:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads
- attacker knowledge of the names of security sensitive files being uploaded
- the security sensitive files also being uploaded via partial PUT

If all of the following were true, a malicious user was able to perform remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with the default storage location
- application included a library that may be leveraged in a deserialization attack

Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.
