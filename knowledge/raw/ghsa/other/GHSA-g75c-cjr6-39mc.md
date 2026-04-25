# XWiki Platform's Mail.MailConfig can be edited by any user with edit rights

**GHSA**: GHSA-g75c-cjr6-39mc | **CVE**: CVE-2023-34465 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-269

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-mail-send-default** (maven): >= 11.8-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-mail-send-default** (maven): >= 14.5, < 14.10.6
- **org.xwiki.platform:xwiki-platform-mail-send-default** (maven): >= 15.0-rc-1, < 15.1

## Description

### Impact

`Mail.MailConfig` can be edited by any logged-in user by default. Consequently, they can:
- change the mail obfuscation configuration
- view and edit the mail sending configuration, including the smtp domain name and credentials.

### Patches
The problem has been patched on XWiki 14.4.8, 15.1, and 14.10.6.

### Workarounds
The rights of the `Mail.MailConfig` page can be manually updated so that only a set of trusted users can view, edit and delete it (e.g., the `XWiki.XWikiAdminGroup` group).
On 14.4.8+, 15.1-rc-1+, or 14.10.5+, if at startup `Mail.MailConfig` does not have any rights defined, `view`, `edit ` and `delete` rights are automatically granted to the `XWiki.XWikiAdminGroup` group.
See the corresponding [patch](https://github.com/xwiki/xwiki-platform/commit/d28d7739089e1ae8961257d9da7135d1a01cb7d4).

### References
- https://jira.xwiki.org/browse/XWIKI-20519 + https://jira.xwiki.org/browse/XWIKI-20671
- https://github.com/xwiki/xwiki-platform/commit/d28d7739089e1ae8961257d9da7135d1a01cb7d4
- https://github.com/xwiki/xwiki-platform/commit/8910b8857d3442d2e8142f655fdc0512930354d1


### For more information

If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)
