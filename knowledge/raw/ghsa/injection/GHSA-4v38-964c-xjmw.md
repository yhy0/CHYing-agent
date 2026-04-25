# Code injection via unescaped translations in xwiki-platform

**GHSA**: GHSA-4v38-964c-xjmw | **CVE**: CVE-2023-29510 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 4.3-milestone-2, < 14.10.2

## Description

### Impact
In XWiki, every user can add translations that are only applied to the current user. This also allows overriding existing translations. Such translations are often included in privileged contexts without any escaping which allows remote code execution for any user who has edit access on at least one document which could be the user's own profile where edit access is enabled by default.

The following describes a proof of concept exploit to demonstrate this vulnerability:

1. Edit the user profile with the wiki editor and set the content to
```
error={{/html}} {{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("hello from groovy!"){{/groovy}}{{/async}}
```
2. Use the object editor to add an object of type `XWiki.TranslationDocumentClass` with scope `USER`.
3. Open the document `WikiManager.AdminWikiDescriptorSheet`.

The expected result would be that a message with title `{{/html}} {{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("hello from groovy!"){{/groovy}}{{/async}}` is displayed while in fact an error that the HTML macro couldn't be executed is displayed, followed by the text "hello from groovy!" and some raw HTML, showing that the Groovy macro has been executed.

### Patches

A mitigation for this vulnerability is part of XWiki 14.10.2 and XWiki 15.0 RC1: translations with user scope now require script right. This means that regular users cannot exploit this anymore as users don't have script right by default anymore starting with XWiki 14.10.

### Workarounds

There are no known workarounds apart from upgrading to a patched versions.

### References

* https://jira.xwiki.org/browse/XWIKI-19749
* https://github.com/xwiki/xwiki-platform/commit/d06ff8a58480abc7f63eb1d4b8b366024d990643

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)
