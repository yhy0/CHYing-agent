# XWiki Platform vulnerable to code injection from view right on XWiki.ClassSheet

**GHSA**: GHSA-mjw9-3f9f-jq2w | **CVE**: CVE-2023-29522 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-xclass-ui** (maven): >= 7.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-xclass-ui** (maven): >= 14.5, < 14.10.3

## Description

### Impact

Any user with view rights can execute arbitrary script macros including Groovy and Python macros that allow remote code execution including unrestricted read and write access to all wiki contents. The attack works by opening a non-existing page with a name crafted to contain a dangerous payload.

For instance: `Open <xwiki-host>/xwiki/bin/view/%22%2F%7D%7D%7B%7B%2Fhtml%7D%7D%20%7B%7Basync%20async%3D%22true%22%20cached%3D%22false%22%20context%3D%22doc.reference%22%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22Hello%20%22%20%2B%20%22from%20groovy!%22)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D?sheet=XWiki.ClassSheet&xpage=view`, where `<xwiki-host>` is the URL of your XWiki installation.

### Patches
This has been patched in XWiki 14.4.8, 14.10.3 and 15.0RC1.

### Workarounds
The fix is only impacting Velocity templates and page contents, so applying this [patch](https://github.com/xwiki/xwiki-platform/commit/d7e56185376641ee5d66477c6b2791ca8e85cfee) is enough to fix the issue.

### References
- https://github.com/xwiki/xwiki-platform/commit/d7e56185376641ee5d66477c6b2791ca8e85cfee
- https://jira.xwiki.org/browse/XWIKI-20456

### For more information

If you have any questions or comments about this advisory:

-    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
-    Email us at [Security Mailing List](mailto:security@xwiki.org)
