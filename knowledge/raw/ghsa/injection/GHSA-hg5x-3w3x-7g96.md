# xwiki-platform-web-templates vulnerable to Eval Injection

**GHSA**: GHSA-hg5x-3w3x-7g96 | **CVE**: CVE-2023-29512 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 1.0B1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 14.5, < 14.10.1

## Description

### Impact
Any user with edit rights on a page (e.g., it's own user page), can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the information loaded from attachments in `imported.vm`, `importinline.vm`, and `packagelist.vm`. This page is installed by default.

Reproduction steps are described in https://jira.xwiki.org/browse/XWIKI-20267

### Patches
The vulnerability has been patched in XWiki 15.0-rc-1, 14.10.1, 14.4.8, and 13.10.11.

### Workarounds
The issue can be fixed by applying this [patch](https://github.com/xwiki/xwiki-platform/commit/e4bbdc23fea0be4ef1921d1a58648028ce753344) on `imported.vm`, `importinline.vm`, and `packagelist.vm`.

### References
- https://github.com/xwiki/xwiki-platform/commit/e4bbdc23fea0be4ef1921d1a58648028ce753344
- https://jira.xwiki.org/browse/XWIKI-20267


### For more information

If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)

