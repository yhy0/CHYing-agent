# XWiki Platform vulnerable to reflected cross-site scripting via back and xcontinue parameters in resubmit template

**GHSA**: GHSA-r8xc-xxh3-q5x3 | **CVE**: CVE-2023-35160 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-79, CWE-87

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 2.5-milestone-2, < 14.10.5
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 15.0-rc-1, < 15.1-rc-1

## Description

### Impact
Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS).
It's possible to exploit the resubmit template to perform a XSS, e.g. by using URL such as:

 > xwiki/bin/view/XWiki/Main?xpage=resubmit&resubmit=javascript:alert(document.domain)&xback=javascript:alert(document.domain)

This vulnerability exists since XWiki 2.5-milestone-2.

### Patches

The vulnerability has been patched in XWiki 14.10.5 and 15.1-rc-1.

### Workarounds

It's possible to workaround the vulnerability by editing the template resubmit.vm to perform checks on it, but note that the appropriate fix involves new APIs that have been recently introduced in XWiki. See the referenced jira tickets.

### References

  * Jira ticket about the vulnerability: https://jira.xwiki.org/browse/XWIKI-20343
  * Introduction of the macro used for fixing all those vulnerabilities: https://jira.xwiki.org/browse/XWIKI-20583
  * Commit containing the actual fix in the page: https://github.com/xwiki/xwiki-platform/commit/dbc92dcdace33823ffd1e1591617006cb5fc6a7f

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been reported by René de Sain @renniepak.
