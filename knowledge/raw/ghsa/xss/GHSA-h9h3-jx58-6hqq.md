# Jenkins Mashup Portlets Plugin vulnerable to stored cross-site scripting

**GHSA**: GHSA-h9h3-jx58-6hqq | **CVE**: CVE-2023-28679 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **javagh.jenkins:mashup-portlets-plugin** (maven): <= 1.1.2

## Description

Jenkins Mashup Portlets Plugin 1.1.2 and earlier provides the "Generic JS Portlet" feature that lets a user populate a portlet using a custom JavaScript expression.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by authenticated attackers with Overall/Read permission.
