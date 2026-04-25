# XWiki Platform vulnerable to cross-site scripting via xcontinue parameter in previewactions template

**GHSA**: GHSA-q9hg-9qj2-mxf9 | **CVE**: CVE-2023-35162 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 6.1-rc-1, < 14.10.5
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 15.0-rc-1, < 15.1-rc-1

## Description

### Impact
Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS).
It's possible to exploit the previewactions template to perform a XSS, e.g. by using URL such as: 
> <hostname>/xwiki/bin/get/FlamingoThemes/Cerulean?xpage=xpart&vm=previewactions.vm&xcontinue=javascript:alert(document.domain)

This vulnerability exists since XWiki 6.1-rc-1. 

### Patches

The vulnerability has been patched in XWiki 14.10.5 and 15.1-rc-1.

### Workarounds

It's possible to workaround the vulnerability by editing the template previewactions.vm to perform checks on it, but note that the appropriate fix involves new APIs that have been recently introduced in XWiki. See the referenced jira tickets. 

### References

  * Jira ticket about the vulnerability: https://jira.xwiki.org/browse/XWIKI-20342
  * Introduction of the macro used for fixing this type of vulnerability: https://jira.xwiki.org/browse/XWIKI-20583
  * Commit containing the actual fix in the template: https://github.com/xwiki/xwiki-platform/commit/9f01166b1a8ee9639666099eb5040302df067e4d

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been reported by René de Sain @renniepak.

