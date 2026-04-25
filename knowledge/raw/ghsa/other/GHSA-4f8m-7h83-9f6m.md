# XWiki Platform vulnerable to CSRF privilege escalation/RCE via the create action

**GHSA**: GHSA-4f8m-7h83-9f6m | **CVE**: CVE-2023-40572 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-352

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 3.2-milestone-3, < 14.10.9
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 15.0-rc-1, < 15.4-rc-1

## Description

### Impact
The create action is vulnerable to a CSRF attack, allowing script and thus remote code execution when targeting a user with script/programming right, thus compromising the confidentiality, integrity and availability of the whole XWiki installation. To reproduce, the XWiki syntax `[[image:path:/xwiki/bin/create/Foo/WebHome?template=&parent=Main.WebHome&title=$services.logging.getLogger(%22foo%22).error(%22Script%20executed!%22)]]` can be added to any place that supports XWiki syntax like a comment. When a user with script right views this image and a log message `ERROR foo - Script executed!` appears in the log, the XWiki installation is vulnerable.

### Patches
This has been patched in XWiki 14.10.9 and 15.4RC1 by requiring a CSRF token for the actual page creation.

### Workarounds
There are no known workarounds.

### References
* https://jira.xwiki.org/browse/XWIKI-20849
* https://github.com/xwiki/xwiki-platform/commit/4b20528808d0c311290b0d9ab2cfc44063380ef7
