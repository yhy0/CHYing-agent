# XWiki Platform's async and display macro allow displaying and interacting with any document in restricted mode

**GHSA**: GHSA-gpq5-7p34-vqx5 | **CVE**: CVE-2023-29526 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74, CWE-284

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 10.11.1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 14.5, < 14.10.3
- **org.xwiki.platform:xwiki-platform-rendering-async-macro** (maven): >= 10.11.1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-rendering-async-macro** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-rendering-async-macro** (maven): >= 14.5, < 14.10.3

## Description

### Impact

It's possible to display any page you cannot access through the combination of the async and display macro. 

Steps to reproduce:

1. Enable comments for guests by giving guests comment rights
2. As a guest, create a comment with content ```{{async}}{{display reference="Menu.WebHome" /}}{{/async}}```
3. Open the comments viewer from the menu (appends ?viewer=comments to the URL)

-> the `Menu.WebHome` is displayed while the expectation would be to have an error that the current user is not allowed to see it

### Patches

The vulnerability has been patched in XWiki 15.0-rc-1, 14.10.3, 14.4.8, and 13.10.11.

### Workarounds

There is no known workaround.

### References

https://jira.xwiki.org/browse/XWIKI-20394
https://jira.xwiki.org/browse/XRENDERING-694

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)
