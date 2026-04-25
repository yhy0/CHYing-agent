# Improper Neutralization of Invalid Characters in Data Attribute Names in org.xwiki.commons:xwiki-commons-xml

**GHSA**: GHSA-pv7v-ph6g-3gxv | **CVE**: CVE-2023-31126 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79, CWE-86

**Affected Packages**:
- **org.xwiki.commons:xwiki-commons-xml** (maven): >= 14.6-rc-1, < 14.10.4

## Description

### Impact
The HTML sanitizer, introduced in version 14.6-rc-1, allowed the injection of arbitrary HTML code and thus cross-site scripting via invalid data attributes. This can be exploited, e.g., via the link syntax in any content that supports XWiki syntax like comments in XWiki: 

```
[[Link1>>https://XWiki.example.com||data-x/onmouseover="alert('XSS1')"]].
```

When a user moves the mouse over this link, the malicious JavaScript code is executed in the context of the user session. When this user is a privileged user who has programming rights, this allows server-side code execution with programming rights, impacting the confidentiality, integrity and availability of the XWiki instance.

Note that this vulnerability does not affect restricted cleaning in HTMLCleaner as there attributes are cleaned and thus characters like `/` and `>` are removed in all attribute names.

### Patches
This problem has been patched in XWiki 14.10.4 and 15.0 RC1 by making sure that data attributes only contain allowed characters.

### Workarounds
There are no known workarounds apart from upgrading to a version including the fix.

### References
* https://jira.xwiki.org/browse/XCOMMONS-2606
* https://github.com/xwiki/xwiki-commons/commit/0b8e9c45b7e7457043938f35265b2aa5adc76a68

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki](https://jira.xwiki.org/)
* Email us at [XWiki Security mailing-list](mailto:security@xwiki.org)
