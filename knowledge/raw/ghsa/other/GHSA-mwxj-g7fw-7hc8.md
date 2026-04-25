# XWiki Platform vulnerable to reflected cross-site scripting via xredirect parameter in restore template

**GHSA**: GHSA-mwxj-g7fw-7hc8 | **CVE**: CVE-2023-35158 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-87

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 9.4-rc-1, < 14.10.5
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 15.0-rc-1, < 15.1-rc-1

## Description

### Impact
Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS).
It's possible to exploit the restore template to perform a XSS, e.g. by using URL such as:

> /xwiki/bin/view/XWiki/Main?xpage=restore&showBatch=true&xredirect=javascript:alert(document.domain)

This vulnerability exists since XWiki 9.4-rc-1.

### Patches

The vulnerability has been patched in XWiki 14.10.5 and 15.1-rc-1. 

### Workarounds

It's possible to workaround the vulnerability by editing the template restore.vm to perform checks on it, but note that the appropriate fix involves new APIs that have been recently introduced in XWiki. See the referenced jira tickets.

### References

  * Vulnerability in restore template: https://jira.xwiki.org/browse/XWIKI-20352
  * Introduction of the macro used for fixing this vulnerability: https://jira.xwiki.org/browse/XWIKI-20583
  * Commit containing the actual fix in the template: https://github.com/xwiki/xwiki-platform/commit/d5472100606c8355ed44ada273e91df91f682738

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

Both vulnerabilities about the delete and restore templates have been reported by René de Sain @renniepak.
