# XWiki Platform vulnerable to privilege escalation from view right on XWiki.Notifications.Code.LegacyNotificationAdministration

**GHSA**: GHSA-jgg7-w2rj-58cj | **CVE**: CVE-2023-29525 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-distribution-war** (maven): >= 12.6.1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-distribution-war** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-distribution-war** (maven): >= 14.5, < 14.6-rc-1
- **org.xwiki.platform:xwiki-platform-legacy-events-hibernate-ui** (maven): >= 14.6-rc-1, < 14.10.3

## Description

### Impact

Steps to reproduce:

Open <xwiki-host>/xwiki/bin/view/XWiki/Notifications/Code/LegacyNotificationAdministration?since=%7B%7B%2Fhtml%7D%7D+%7B%7Basync+async%3D%22true%22+cached%3D%22false%22+context%3D%22doc.reference%22%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22Hello+%22+%2B+%22from+groovy%21%22%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D, where <xwiki-host> is the URL of your XWiki installation.

This demonstrates an XWiki syntax injection attack via the since-parameter, allowing privilege escalation from view to programming rights.

### Patches

The vulnerability has been patched in XWiki 15.0-rc-1, 14.10.3, 14.4.8 and 14.10.3.

### Workarounds

For versions >= 14.6-rc-1 the workaround is to modify the page `XWiki.Notifications.Code.LegacyNotificationAdministration` to add the missing escaping, as described on https://github.com/xwiki/xwiki-platform/commit/8e7c7f90f2ddaf067cb5b83b181af41513028754#diff-4e13f4ee4a42938bf1201b7ee71ca32edeacba22559daf0bcb89d534e0225949R70

For versions < 14.6-rc-1 the workaround is to modify the file `<xwikiwebapp>/templates/distribution/eventmigration.wiki` to add the missing escaping, as described on https://github.com/xwiki/xwiki-platform/commit/6d74e2e4aa03d19f0be385ab63ae9e0f0e90a766

### References

https://jira.xwiki.org/browse/XWIKI-20287

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)
