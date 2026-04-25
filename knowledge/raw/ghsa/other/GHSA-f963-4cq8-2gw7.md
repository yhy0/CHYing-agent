# In XWiki Platform, payloads stored in content is executed when a user with script/programming right edit them

**GHSA**: GHSA-f963-4cq8-2gw7 | **CVE**: CVE-2024-43401 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269, CWE-862

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): < 15.10-rc-1

## Description

### Impact

A user without script/programming right can trick a user with elevated rights to edit a content with a malicious payload using a WYSIWYG editor.
The user with elevated rights is not warned beforehand that they are going to edit possibly dangerous content.
The payload is executed at edit time.

### Patches

This vulnerability has been patched in XWiki 15.10RC1.

### Workarounds

No workaround. It is advised to upgrade to XWiki 15.10+.

### References

* https://jira.xwiki.org/browse/XWIKI-20331
* https://jira.xwiki.org/browse/XWIKI-21311
* https://jira.xwiki.org/browse/XWIKI-21481
* https://jira.xwiki.org/browse/XWIKI-21482
* https://jira.xwiki.org/browse/XWIKI-21483
* https://jira.xwiki.org/browse/XWIKI-21484
* https://jira.xwiki.org/browse/XWIKI-21485
* https://jira.xwiki.org/browse/XWIKI-21486
* https://jira.xwiki.org/browse/XWIKI-21487
* https://jira.xwiki.org/browse/XWIKI-21488
* https://jira.xwiki.org/browse/XWIKI-21489
* https://jira.xwiki.org/browse/XWIKI-21490

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been reported on Intigriti by @floerer
