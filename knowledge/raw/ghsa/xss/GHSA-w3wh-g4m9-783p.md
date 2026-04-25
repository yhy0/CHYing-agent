# XWiki Rendering is vulnerable to XSS attacks through insecure XHTML syntax

**GHSA**: GHSA-w3wh-g4m9-783p | **CVE**: CVE-2025-53835 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79, CWE-80

**Affected Packages**:
- **org.xwiki.rendering:xwiki-rendering-syntax-xhtml** (maven): >= 5.4.5, < 14.10

## Description

### Impact
The XHTML syntax depended on the `xdom+xml/current` syntax which allows the creation of raw blocks that permit the insertion of arbitrary HTML content including JavaScript. This allows XSS attacks for users who can edit a document like their user profile (enabled by default). The attack works by setting the document's syntax to `xdom+xml/current` and then inserting content like
```
<document><p><metadata><metadata><entry><string>syntax</string><org.xwiki.rendering.syntax.Syntax><type><name>XHTML</name><id>xhtml</id><variants class="empty-list"></variants></type><version>5</version></org.xwiki.rendering.syntax.Syntax></entry></metadata></metadata></p><rawtext syntax="html/5.0" content="&lt;script&gt;alert(1);&lt;/script&gt;"></rawtext></document>
```

This has been fixed by removing the dependency on the `xdom+xml/current` syntax from the XHTML syntax. Note that the `xdom+xml` syntax is still vulnerable to this attack. As it's main purpose is testing and its use is quite difficult, this syntax shouldn't be installed or used on a regular wiki. We're currently not aware of any further dependencies on it.

### Patches
The fix of removing the dependency has been included in XWiki 14.10. It is not released for earlier versions due to the potential breakages, among others this change makes it necessary to update the [Confluence XHTML syntax](https://extensions.xwiki.org/xwiki/bin/view/Extension/Confluence/Syntax%20XHTML/) as it relies on internals that were changed for the fix. Similar XSS fixes were also not applied to the LTS version 13.10.x due to the potential breakages.

### Workarounds
There are no known workarounds apart from upgrading.

### References
* https://jira.xwiki.org/browse/XRENDERING-660
* https://github.com/xwiki/xwiki-rendering/commit/a4ca31f99f524b9456c64150d6f375984aa81ea7

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)
