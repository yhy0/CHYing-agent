# XWiki Platform privilege escalation (PR) from account through AWM content fields

**GHSA**: GHSA-5mf8-v43w-mfxp | **CVE**: CVE-2023-40177 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-appwithinminutes-ui** (maven): >= 4.3-milestone-2, < 14.10.5

## Description

### Impact

Any registered user can use the content field of their user profile page to execute arbitrary scripts with programming rights, thus effectively performing rights escalation.

The problem is present [since version 4.3M2](https://jira.xwiki.org/browse/XWIKI-7369) when AppWithinMinutes Application added support for the Content field, allowing any wiki page (including the user profile page) to use its content as an AWM Content field, which has a custom displayer that executes the content with the rights of the ``AppWithinMinutes.Content`` author, rather than the rights of the content author.

### Patches

The issue has been fixed in XWiki 14.10.5 and 15.1RC1 by https://github.com/xwiki/xwiki-platform/commit/dfb1cde173e363ca5c12eb3654869f9719820262 . The fix is in the content of the [AppWithinMinutes.Content](https://github.com/xwiki/xwiki-platform/commit/dfb1cde173e363ca5c12eb3654869f9719820262#diff-850f6875c40cf7932f40a985e99679a041891c6ee75d10239c06921c0019cf78R82) page that defines the custom displayer. By using the ``display`` script service to render the content we make sure that the proper author is used for access rights checks.

### Workarounds

If you want to fix this problem on older versions of XWiki that have not been patched then you need to modify the content of ``AppWithinMinutes.Content`` page to use the ``display`` script service to render the content, like this:

```
- {{html}}$tdoc.getRenderedContent($tdoc.content, $tdoc.syntax.toIdString()).replace('{{', '&amp;#123;&amp;#123;'){{/html}}
+ {{html}}$services.display.content($tdoc, {
+   'displayerHint': 'default'
+ }).replace('{{/html}}', '&amp;#123;&amp;#123;/html&amp;#125;&amp;#125;'){{/html}}
```

### References

* JIRA issue https://jira.xwiki.org/browse/XWIKI-19906
* Fix https://github.com/xwiki/xwiki-platform/commit/dfb1cde173e363ca5c12eb3654869f9719820262

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been found and reported by @michitux .
