# Privilege escalation (PR)/remote code execution from account through Menu.UIExtensionSheet

**GHSA**: GHSA-v2rr-xw95-wcjx | **CVE**: CVE-2023-37909 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-menu** (maven): >= 5.1-rc-1, < 14.10.8
- **org.xwiki.platform:xwiki-platform-menu-ui** (maven): >= 5.1-rc-1, < 14.10.8
- **org.xwiki.platform:xwiki-platform-menu-ui** (maven): >= 15.0-rc-1, < 15.3-rc-1

## Description

### Impact
Any user who can edit their own user profile can execute arbitrary script macros including Groovy and Python macros that allow remote code execution including unrestricted read and write access to all wiki contents. This can be reproduced with the following steps:

1. As an advanced user, use the object editor to add an object of type `UIExtensionClass` to your user profile. Set the value "Extension Point ID" to `{{/html}}{{async async=false cache=false}}{{groovy}}println("Hello from Groovy!"){{/groovy}}{{/async}}`
2. Open `<xwiki-host>/xwiki/bin/edit/XWiki/<username>?sheet=Menu.UIExtensionSheet` where `<xwiki-host>` is the URL of your XWiki installation and `<username>` is your user name.

If the text `Hello from Groovy!" selected="selected">` is displayed in the output, the attack succeeded.

### Patches

This has been patched in XWiki 14.10.8 and 15.3 RC1 by adding proper escaping.

### Workarounds
The [patch](https://github.com/xwiki/xwiki-platform/commit/9e8f080094333dec63a8583229a3799208d773be#diff-47a5652d0c8e4601dac12bd9ab34b8bd688cb22a1b758ce7b774043658834662) can be manually applied to the document `Menu.UIExtensionSheet`, only three lines need to be changed.

### References

* https://jira.xwiki.org/browse/XWIKI-20746
* https://github.com/xwiki/xwiki-platform/commit/9e8f080094333dec63a8583229a3799208d773be
