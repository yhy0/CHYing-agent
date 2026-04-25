# org.xwiki.platform:xwiki-platform-rendering-macro-rss Cross-site Scripting vulnerability

**GHSA**: GHSA-c885-89fw-55qr | **CVE**: CVE-2023-29202 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.platform:xwiki-core-rendering-macro-rss** (maven): >= 1.8, <= 3.0.1
- **org.xwiki.platform:xwiki-platform-rendering-macro-rss** (maven): < 14.6-rc-1

## Description

### Impact
The [RSS macro](https://extensions.xwiki.org/xwiki/bin/view/Extension/RSS%20Macro) that is bundled in XWiki included the content of the feed items without any cleaning in the HTML output when the parameter `content` was set to `true`. This allowed arbitrary HTML and in particular also JavaScript injection and thus cross-site scripting (XSS) by specifying an RSS feed with malicious content. With the interaction of a user with programming rights, this could be used to execute arbitrary actions in the wiki, including privilege escalation, remote code execution, information disclosure, modifying or deleting content and sabotaging the wiki.

The issue can be reproduced by inserting the following XWiki syntax in any wiki page like the user account:

```javascript
{{rss feed="https://xssrss.blogspot.com/feeds/posts/default?alt=rss" content="true" /}}
```

If an alert is displayed when viewing the page, the wiki is vulnerable.

### Patches
The issue has been patched in XWiki 14.6 RC1, the content of the feed is now properly cleaned before being displayed.

### Workarounds
If the RSS macro isn't used in the wiki, the macro can be uninstalled by deleting `WEB-INF/lib/xwiki-platform-rendering-macro-rss-XX.jar`, where `XX` is XWiki's version, in the web application's directory.

### References
* https://github.com/xwiki/xwiki-platform/commit/5c7ebe47c2897e92d8f04fe2e15027e84dc3ec03
* https://jira.xwiki.org/browse/XWIKI-19671

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

