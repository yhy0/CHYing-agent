# XWiki Platform vulnerable to cross-site scripting in target parameter via share page by email

**GHSA**: GHSA-fwwj-wg89-7h4c | **CVE**: CVE-2023-35155 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-sharepage-api** (maven): >= 2.6-rc-2, < 14.4.8
- **org.xwiki.platform:xwiki-platform-sharepage-api** (maven): >= 14.5, < 14.10.4

## Description

### Impact
Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS).
For instance, the following URL execute an `alter` on the browser: `<xwiki-host>/xwiki/bin/view/Main/?viewer=share&send=1&target=&target=%3Cimg+src+onerror%3Dalert%28document.domain%29%3E+%3Cimg+src+onerror%3Dalert%28document.domain%29%3E+%3Crenniepak%40intigriti.me%3E&includeDocument=inline&message=I+wanted+to+share+this+page+with+you.`, where `<xwiki-host>` is the URL of your XWiki installation.
See https://jira.xwiki.org/browse/XWIKI-20370 for me details.

### Patches

The vulnerability has been patched in XWiki 15.0-rc-1, 14.10.4, and 14.4.8.

### Workarounds
The fix is only impacting Velocity templates and page contents, so applying this [patch](https://github.com/xwiki/xwiki-platform/commit/ca88ebdefb2c9fa41490959cce9f9e62404799e7) is enough to fix the issue.

### References
https://jira.xwiki.org/browse/XWIKI-20370

### For more information

If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been reported on Intigriti by René de Sain @renniepak.
