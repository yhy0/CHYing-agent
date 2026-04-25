# XWiki Platform vulnerable to reflected cross-site scripting via xredirect parameter in deletespace template

**GHSA**: GHSA-x234-mg7q-m8g8 | **CVE**: CVE-2023-35159 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-79, CWE-87

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 3.4-milestone-1, < 14.10.5
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 15.0-rc-1, < 15.1-rc-1

## Description

### Impact
Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS).
It's possible to exploit the deletespace template to perform a XSS, e.g. by using URL such as:

> xwiki/bin/deletespace/Sandbox/?xredirect=javascript:alert(document.domain)

This vulnerability exists since XWiki 3.4-milestone-1.

### Patches
The vulnerability has been patched in XWiki 14.10.5 and 15.1-rc-1.

### Workarounds

It's possible to workaround the vulnerability by editing the template deletespace.vm to perform checks on it, but note that the appropriate fix involves new APIs that have been recently introduced in XWiki. See the referenced jira tickets.

### References

  * Jira ticket about the vulnerability: https://jira.xwiki.org/browse/XWIKI-20612
  * Introduction of the macro used for fixing all those vulnerabilities: https://jira.xwiki.org/browse/XWIKI-20583
  * Commit containing the actual fix in the template: https://github.com/xwiki/xwiki-platform/commit/5c20ff5e3bdea50f1053fe99a27e011b8d0e4b34

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

