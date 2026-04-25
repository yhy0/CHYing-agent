# XWiki allows remote code execution from account through macro descriptions and XWiki.XWikiSyntaxMacrosList

**GHSA**: GHSA-2r87-74cx-2p7c | **CVE**: CVE-2024-55877 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-96

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-help-ui** (maven): >= 9.7-rc-1, < 15.10.11
- **org.xwiki.platform:xwiki-platform-help-ui** (maven): >= 16.0.0-rc-1, < 16.4.1
- **org.xwiki.platform:xwiki-platform-help-ui** (maven): >= 16.5.0-rc-1, < 16.5.0

## Description

### Impact
Any user with an account can perform arbitrary remote code execution by adding instances of `XWiki.WikiMacroClass` to any page. This compromises the confidentiality, integrity and availability of the whole XWiki installation.

To reproduce on a instance, as a connected user without script nor programming rights, go to your user profile and add an object of type `XWiki.WikiMacroClass`. Set "Macro Id", "Macro Name" and "Macro Code" to any value, "Macro Visibility" to `Current User` and "Macro Description" to `{{async}}{{groovy}}println("Hello from User macro!"){{/groovy}}{{/async}}`.
Save the page, then go to `<host>/xwiki/bin/view/XWiki/XWikiSyntaxMacrosList`.
If the description of your new macro reads "Hello from User macro!", then your instance is vulnerable.

### Patches
This vulnerability has been fixed in XWiki 15.10.11, 16.4.1 and 16.5.0.

### Workarounds
It is possible to manually apply [this patch](https://github.com/xwiki/xwiki-platform/commit/40e1afe001d61eafdf13f3621b4b597a0e58a3e3#diff-92fee29683e671b8bc668e3cf4295713d6259f715e3954876049f9de77c0a9ef) to the page `XWiki.XWikiSyntaxMacrosList`.

### References

* https://jira.xwiki.org/browse/XWIKI-22030
* https://github.com/xwiki/xwiki-platform/commit/40e1afe001d61eafdf13f3621b4b597a0e58a3e3
