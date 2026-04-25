# xwiki-platform-administration-ui vulnerable to privilege escalation

**GHSA**: GHSA-rfh6-mg6h-h668 | **CVE**: CVE-2023-29511 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 1.5M2, < 13.10.11
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 14.5, < 14.10.1

## Description

### Impact
Any user with edit rights on a page (e.g., it's own user page), can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the section ids in `XWiki.AdminFieldsDisplaySheet`. This page is installed by default.

Reproduction steps are described in https://jira.xwiki.org/browse/XWIKI-20261

### Patches
The vulnerability has been patched in XWiki  15.0-rc-1, 14.10.1, 14.4.8, and 13.10.11.

### Workarounds
The issue can be fixed by applying this [patch](https://github.com/xwiki/xwiki-platform/commit/f1e310826a19acdcdecdecdcfe171d21f24d6ede) on `XWiki.AdminFieldsDisplaySheet`.

### For more information
If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)

