# org.xwiki.commons:xwiki-commons-xml Cross-site Scripting vulnerability

**GHSA**: GHSA-m3jr-cvhj-f35j | **CVE**: CVE-2023-29201 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.commons:xwiki-commons-xml** (maven): >= 4.2-milestone-1, < 14.6-rc-1

## Description

### Impact
The "restricted" mode of the HTML cleaner in XWiki, introduced in version 4.2-milestone-1, only escaped `<script>` and `<style>`-tags but neither attributes that can be used to inject scripts nor other dangerous HTML tags like `<iframe>`. As a consequence, any code relying on this "restricted" mode for security is vulnerable to JavaScript injection ("cross-site scripting"/XSS). An example are anonymous comments in XWiki where the HTML macro filters HTML using restricted mode:

```javascript
{{html}}
<a href='' onclick='alert(1)'>XSS</a>
{{/html}}
```

When a privileged user with programming rights visits such a comment in XWiki, the malicious JavaScript code is executed in the context of the user session. This allows server-side code execution with programming rights, impacting the confidentiality, integrity and availability of the XWiki instance.

### Patches
This problem has been patched in XWiki 14.6 RC1 with the introduction of a filter with allowed HTML elements and attributes that is enabled in restricted mode.

### Workarounds
There are no known workarounds apart from upgrading to a version including the fix.

### References
* https://github.com/xwiki/xwiki-commons/commit/b11eae9d82cb53f32962056b5faa73f3720c6182 - the patch with the filter
* https://github.com/xwiki/xwiki-commons/commit/4a185e0594d90cd4916d60aa60bb4333dc5623b2 - the patch with the definitions what is allowed
* https://jira.xwiki.org/browse/XWIKI-9118 - the security issue with the HTML macro
* https://jira.xwiki.org/browse/XCOMMONS-1680 - the issue regarding a definition of what is allowed HTML
* https://jira.xwiki.org/browse/XCOMMONS-2426 - the issue regarding the filter that fixes the security issue

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki](https://jira.xwiki.org/)
* Email us at [XWiki Security mailing-list](mailto:security@xwiki.org)
