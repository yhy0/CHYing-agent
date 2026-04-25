# Improper Neutralization of Script-Related HTML Tags (XSS) in the LiveTable Macro

**GHSA**: GHSA-6vgh-9r3c-2cxp | **CVE**: CVE-2023-29207 | **Severity**: high (CVSS 8.9)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 1.9-milestone-2, < 13.10.10
- **org.xwiki.platform:xwiki-platform-flamingo-skin** (maven): >= 1.9-milestone-2, < 13.10.10
- **org.xwiki.platform:xwiki-platform-flamingo** (maven): >= 1.9-milestone-2, < 13.10.10
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 1.9-milestone-2, < 13.10.10
- **org.xwiki.platform:xwiki-platform-web** (maven): >= 1.9-milestone-2, < 13.10.10
- **org.xwiki.platform:xwiki-web-standard** (maven): >= 1.9-milestone-2, < 13.10.10
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 14.0-rc-1, < 14.4.6
- **org.xwiki.platform:xwiki-platform-flamingo-skin** (maven): >= 14.0-rc-1, < 14.4.6
- **org.xwiki.platform:xwiki-platform-flamingo** (maven): >= 14.0-rc-1, < 14.4.6
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 14.0-rc-1, < 14.4.6
- **org.xwiki.platform:xwiki-platform-web** (maven): >= 14.0-rc-1, < 14.4.6
- **org.xwiki.platform:xwiki-web-standard** (maven): >= 14.0-rc-1, < 14.4.6
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 14.5, < 14.9
- **org.xwiki.platform:xwiki-platform-flamingo-skin** (maven): >= 14.5, < 14.9
- **org.xwiki.platform:xwiki-platform-flamingo** (maven): >= 14.5, < 14.9
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 14.5, < 14.9
- **org.xwiki.platform:xwiki-platform-web** (maven): >= 14.5, < 14.9
- **org.xwiki.platform:xwiki-web-standard** (maven): >= 14.5, < 14.9

## Description

### Impact
The [Livetable Macro](https://extensions.xwiki.org/xwiki/bin/view/Extension/Livetable%20Macro) wasn't properly sanitizing column names, thus allowing the insertion of raw HTML code including JavaScript. This vulnerability was also exploitable via the [Documents Macro](https://extensions.xwiki.org/xwiki/bin/view/Extension/Documents%20Macro) that is included since XWiki 3.5M1 and doesn't require script rights, this can be demonstrated with the syntax `{{documents id="example" count="5" actions="false" columns="doc.title, before<script>alert(1)</script>after"/}}`. Therefore, this can also be exploited by users without script right and in comments. With the interaction of a user with more rights, this could be used to execute arbitrary actions in the wiki, including privilege escalation, remote code execution, information disclosure, modifying or deleting content.

### Patches
This has been patched in XWiki 14.9, 14.4.6, and 13.10.10.

### Workarounds
It is possible to apply the [patch](https://github.com/xwiki/xwiki-platform/commit/65ca06c51e7a1d5a579344c7272b2cc9a9a21126) to existing installations without upgrading. Only the files `skins/flamingo/macros.vm` and `templates/macros.vm` in the web application directory need to be replaced by a patched version.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

