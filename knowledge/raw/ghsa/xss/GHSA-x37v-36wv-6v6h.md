# Cross-site Scripting in org.xwiki.commons:xwiki-commons-xml

**GHSA**: GHSA-x37v-36wv-6v6h | **CVE**: CVE-2023-29528 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.commons:xwiki-commons-xml** (maven): >= 4.2-milestone-1, < 14.10

## Description

### Impact
The "restricted" mode of the HTML cleaner in XWiki, introduced in version 4.2-milestone-1 and massively improved in version 14.6-rc-1, allowed the injection of arbitrary HTML code and thus cross-site scripting via invalid HTML comments. As a consequence, any code relying on this "restricted" mode for security is vulnerable to JavaScript injection ("cross-site scripting"/XSS). An example are anonymous comments in XWiki where the HTML macro filters HTML using restricted mode:

```html
{{html}}
<!--> <Details Open OnToggle=confirm("XSS")>
{{/html}}
```

When a privileged user with programming rights visits such a comment in XWiki, the malicious JavaScript code is executed in the context of the user session. This allows server-side code execution with programming rights, impacting the confidentiality, integrity and availability of the XWiki instance.

Note that while all versions since 4.2-milestone-1 should be vulnerable, only starting with version 14.6-rc-1 the HTML comment is necessary for the attack to succeed due to [another vulnerability](https://github.com/xwiki/xwiki-commons/security/advisories/GHSA-m3jr-cvhj-f35j) that has been patched in version 14.6-rc-1.

### Patches
This problem has been patched in XWiki 14.10, HTML comments are now removed in restricted mode and a check has been introduced that ensures that comments don't start with `>`.

### Workarounds
There are no known workarounds apart from upgrading to a version including the fix.

### References
* https://jira.xwiki.org/browse/XCOMMONS-2568
* https://jira.xwiki.org/browse/XWIKI-20348
* https://github.com/xwiki/xwiki-commons/commit/8ff1a9d7e5d7b45b690134a537d53dc05cae04ab

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki](https://jira.xwiki.org/)
* Email us at [XWiki Security mailing-list](mailto:security@xwiki.org)

### Attribution

This vulnerability was reported on Intigriti by [ynoof](https://twitter.com/ynoofAssiri) @Ynoof5.

