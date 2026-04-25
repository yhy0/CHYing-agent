# WSO2 API Manager XML External Entity (XXE) vulnerability

**GHSA**: GHSA-h94w-8qhg-3xmc | **CVE**: CVE-2025-2905 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-611

**Affected Packages**:
- **org.wso2.am:am-distribution-parent** (maven): < 2.1.0

## Description

An XML External Entity (XXE) vulnerability exists in the gateway component of WSO2 API Manager due to insufficient validation of XML input in crafted URL paths. User-supplied XML is parsed without appropriate restrictions, enabling external entity resolution.

This vulnerability can be exploited by an unauthenticated remote attacker to read files from the server’s filesystem or perform denial-of-service (DoS) attacks.

  *  On systems running JDK 7 or early JDK 8, full file contents may be exposed.

  *  On later versions of JDK 8 and newer, only the first line of a file may be read, due to improvements in XML parser behavior.

  *  DoS attacks such as "Billion Laughs" payloads can cause service disruption.
