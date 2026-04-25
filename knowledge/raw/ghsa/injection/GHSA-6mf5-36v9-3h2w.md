# XWiki Platform vulnerable to privilege escalation (PR) from view right via Invitation application

**GHSA**: GHSA-6mf5-36v9-3h2w | **CVE**: CVE-2023-35150 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 2.4-m-2, < 14.4.8
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 14.5, < 14.10.4
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 15.0-rc-1, < 15.0

## Description

### Impact
Any user with view rights on any document can execute code with programming rights, leading to remote code execution by crafting an url with a dangerous payload. See the example below:
Open `<xwiki-host>/xwiki/bin/view/%5D%5D%20%7B%7Basync%20async%3D%22true%22%20cached%3D%22false%22%20context%3D%22doc.reference%22%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22Hello%20%22%20%2B%20%22from%20groovy!%22)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D?sheet=Invitation.InvitationGuestActions&xpage=view` where `<xwiki-host>` is the URL of your XWiki installation.

### Patches
The problem as been patching on XWiki 15.0, 14.10.4 and 14.4.8.

### Workarounds
It is possible to partially fix the issue by applying this [patch](https://github.com/xwiki/xwiki-platform/commit/b65220a4d86b8888791c3b643074ebca5c089a3a). Note that some additional issue can remain and can be fixed automatically by a migration. Hence, it is advised to upgrade to one of the patched version instead of patching manually.

### References
- https://jira.xwiki.org/browse/XWIKI-20285

### For more information

If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)
