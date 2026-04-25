# XWiki Platform vulnerable to reflected cross-site scripting via xredirect parameter in delete template

**GHSA**: GHSA-834c-x29c-f42c | **CVE**: CVE-2023-35156 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-79, CWE-87

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 6.0-rc-1, < 14.10.6
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 15.0-rc-0, < 15.1

## Description

### Impact

Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS).
It's possible to exploit the delete template to perform a XSS, e.g. by using URL such as:

> xwiki/bin/get/FlamingoThemes/Cerulean?xpage=xpart&vm=delete.vm&xredirect=javascript:alert(document.domain)

This vulnerability exists since XWiki 6.0-rc-1.

### Patches

The vulnerability has been patched in XWiki 14.10.6 and 15.1. Note that a partial patch has been provided in 14.10.5 but wasn't enough to entirely fix the vulnerability. 

### Workarounds

It's possible to workaround the vulnerability by editing the template delete.vm to perform checks on it, but note that the appropriate fix involves new APIs that have been recently introduced in XWiki. See the referenced jira tickets.

### References

  * Jira ticket about the original vulnerability: https://jira.xwiki.org/browse/XWIKI-20341
  * Commit containing the first fix in the template: https://github.com/xwiki/xwiki-platform/commit/e80d22d193df364b07bab7925572720f91a8984a
  * Jira ticket about the second part of the vulnerability found after 14.10.5: https://jira.xwiki.org/browse/XWIKI-20672
  * Commits containing the second fix in the template: 
    * https://github.com/xwiki/xwiki-platform/commit/13875a6437d4525ac4aeea25918f2d2dffac9ee1
    * https://github.com/xwiki/xwiki-platform/commit/24ec12890ac7fa6daec8d0b3435cfcba11362fd5
  * Introduction of the macro used for fixing all those vulnerabilities: https://jira.xwiki.org/browse/XWIKI-20583

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been reported by René de Sain @renniepak.
