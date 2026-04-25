# Improper Authentication vulnerability in Apache Solr

**GHSA**: GHSA-mjvf-4h88-6xm3 | **CVE**: CVE-2024-45216 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287, CWE-863

**Affected Packages**:
- **org.apache.solr:solr** (maven): >= 5.3.0, < 8.11.4
- **org.apache.solr:solr** (maven): >= 9.0.0, < 9.7.0

## Description

Solr instances using the PKIAuthenticationPlugin, which is enabled by default when Solr Authentication is used, are vulnerable to Authentication bypass. A fake ending at the end of any Solr API URL path, will allow requests to skip Authentication while maintaining the API contract with the original URL Path. This fake ending looks like an unprotected API path, however it is stripped off internally after authentication but before API routing.


This issue affects Apache Solr: from 5.3.0 before 8.11.4, from 9.0.0 before 9.7.0.

Users are recommended to upgrade to version 9.7.0, or 8.11.4, which fix the issue.
