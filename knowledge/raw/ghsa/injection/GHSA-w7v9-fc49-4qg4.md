# org.xwiki.platform:xwiki-platform-wiki-ui-mainwiki Eval Injection vulnerability

**GHSA**: GHSA-w7v9-fc49-4qg4 | **CVE**: CVE-2023-29211 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-wiki-ui-mainwiki** (maven): >= 5.3-milestone-2, < 13.10.11
- **org.xwiki.platform:xwiki-platform-wiki-ui-mainwiki** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-wiki-ui-mainwiki** (maven): >= 14.5, < 14.10

## Description

### Impact
Any user with view rights `WikiManager.DeleteWiki` can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the `wikiId` url parameter.

A proof of concept exploit is to open <xwiki-host>/xwiki/bin/view/WikiManager/DeleteWiki?wikiId=%22+%2F%7D%7D+%7B%7Basync+async%3D%22true%22+cached%3D%22false%22+context%3D%22doc.reference%22%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22Hello+from+groovy%21%22%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D where <xwiki-host> is the URL of your XWiki installation.

### Patches
The problem has been patched on XWiki  13.10.11, 14.4.7, and 14.10.

### Workarounds
The issue can be fixed manually applying this [patch](https://github.com/xwiki/xwiki-platform/commit/ba4c76265b0b8a5e2218be400d18f08393fe1428#diff-64f39f5f2cc8c6560a44e21a5cfd509ef00e8a2157cd9847c9940a2e08ea43d1R63-R64).

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

