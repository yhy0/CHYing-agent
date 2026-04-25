# Bitbucket Server Integration Plugin allows bypassing CSRF protection for any URL

**GHSA**: GHSA-qjw6-xvrm-5f2h | **CVE**: CVE-2025-24398 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **io.jenkins.plugins:atlassian-bitbucket-server-integration** (maven): >= 2.1.0, < 4.1.4

## Description

An extension point in Jenkins allows selectively disabling cross-site request forgery (CSRF) protection for specific URLs. Bitbucket Server Integration Plugin implements this extension point to support OAuth 1.0 authentication.

In Bitbucket Server Integration Plugin 2.1.0 through 4.1.3 (both inclusive) this implementation is too permissive, allowing attackers to craft URLs that would bypass the CSRF protection of any target URL.

Bitbucket Server Integration Plugin 4.1.4 restricts which URLs it disables cross-site request forgery (CSRF) protection for to the URLs that needs it.
