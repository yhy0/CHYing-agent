# XWiki Platform vulnerable to remote code execution through the section parameter in Administration as guest

**GHSA**: GHSA-62pr-qqf7-hh89 | **CVE**: CVE-2023-46731 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): < 14.10.14
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 15.0-rc-1, < 15.5.1
- **org.xwiki.platform:xwiki-platform-administration** (maven): < 14.10.14

## Description

### Impact
XWiki doesn't properly escape the section URL parameter that is used in the code for displaying administration sections. This allows any user with read access to the document `XWiki.AdminSheet` (by default, everyone including unauthenticated users) to execute code including Groovy code. This impacts the confidentiality, integrity and availability of the whole XWiki instance.

By opening the URL `<server>/xwiki/bin/get/Main/WebHome?sheet=XWiki.AdminSheet&viewer=content&section=%5D%5D%7B%7B%2Fhtml%7D%7D%7B%7Basync%7D%7D%7B%7Bgroovy%7D%7Dservices.logging.getLogger(%22attacker%22).error(%22Attack%20succeeded!%22)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D&xpage=view` where `<server>` is the URL of the XWiki installation, it can be tested if an XWiki installation is vulnerable. If this causes a log message `ERROR attacker                       - Attack succeeded!` to appear in XWiki's log, the installation is vulnerable. In very old versions of XWiki, the attack can be demonstrated with `<server>/xwiki/bin/get/XWiki/XWikiPreferences?section=%3C%25println(%22Hello%20from%20Groovy%22)%25%3E&xpage=view` which displays `admin.hello from groovy` as title when the attack succeeds (tested on XWiki 1.7).

### Patches
This vulnerability has been patched in XWiki 14.10.14, 15.6 RC1 and 15.5.1.

### Workarounds
The [fix](https://github.com/xwiki/xwiki-platform/commit/fec8e0e53f9fa2c3f1e568cc15b0e972727c803a#diff-6271f9be501f30b2ba55459eb451aee3413d34171ba8198a77c865306d174e23), which consists of replacing `= $services.localization.render("administration.sectionTitle$level", [$sectionName]) =` by `= $services.localization.render("administration.sectionTitle$level", 'xwiki/2.1', [$sectionName]) =`, can be applied manually to the document `XWiki.AdminSheet`.

### References
* https://jira.xwiki.org/browse/XWIKI-21110
* https://github.com/xwiki/xwiki-platform/commit/fec8e0e53f9fa2c3f1e568cc15b0e972727c803a
