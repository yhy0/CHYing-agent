# XWiki Platform vulnerable to Code Injection in icon themes

**GHSA**: GHSA-fm68-j7ww-h9xf | **CVE**: CVE-2023-36470 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-icon-default** (maven): >= 6.2-milestone-1, < 14.10.6
- **org.xwiki.platform:xwiki-platform-icon-script** (maven): >= 6.2-milestone-1, < 14.10.6
- **org.xwiki.platform:xwiki-platform-icon-script** (maven): >= 15.0-rc-1, < 15.2-rc-1
- **org.xwiki.platform:xwiki-platform-icon-default** (maven): >= 15.0-rc-1, < 15.2-rc-1
- **org.xwiki.platform:xwiki-platform-icon-ui** (maven): >= 6.2-milestone-1, < 14.10.6
- **org.xwiki.platform:xwiki-platform-icon-ui** (maven): >= 15.0-rc-1, < 15.2-rc-1

## Description

### Impact
By either creating a new or editing an existing document with an icon set, an attacker can inject XWiki syntax and Velocity code that is executed with programming rights and thus allows remote code execution. There are different attack vectors, the simplest is the Velocity code in the icon set's HTML or XWiki syntax definition. The [icon picker](https://extensions.xwiki.org/xwiki/bin/view/Extension/Icon%20Theme%20Application#HIconPicker) can be used to trigger the rendering of any icon set. The XWiki syntax variant of the icon set is also used without any escaping in some documents, allowing to inject XWiki syntax including script macros into a document that might have programming right, for this the currently used icon theme needs to be edited. Further, the HTML output of the icon set is output as JSON in the icon picker and this JSON is interpreted as XWiki syntax, allowing again the injection of script macros into a document with programming right and thus allowing remote code execution. This impacts the confidentiality, integrity and availability of the whole XWiki instance.

### Patches

This has been patched in XWiki 14.10.6 and 15.1. Icon themes now require script right and the code in the icon theme is executed within the context of the icon theme, preventing any rights escalation. A macro for displaying icons has been introduced to avoid injecting the raw wiki syntax of an icon set into another document.

### Workarounds
There are no workarounds apart from upgrading to a version containing the fix.

### References

* https://jira.xwiki.org/browse/XWIKI-20524
* https://github.com/xwiki/xwiki-platform/commit/b0cdfd893912baaa053d106a92e39fa1858843c7
* https://github.com/xwiki/xwiki-platform/commit/46b542854978e9caa687a5c2b8817b8b17877d94
* https://github.com/xwiki/xwiki-platform/commit/79418dd92ca11941b46987ef881bf50424898ff4

