# XWiki vulnerable to Code Injection in template provider administration

**GHSA**: GHSA-9j36-3cp4-rh4j | **CVE**: CVE-2023-29514 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform.applications:xwiki-application-administration** (maven): >= 1.35, <= 1.49
- **org.xwiki.platform:xwiki-platform-administration** (maven): >= 3.1-milestone-1, < 4.2-milestone-1
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 4.2-milestone-1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 14.5, < 14.10.1

## Description

### Impact

Any user with edit rights on any document (e.g., the own user profile) can execute code with programming rights, leading to remote code execution by following these steps:

1. Set the title of any document you can edit (can be the user profile) to
```
    {{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("Hello " + "from groovy!"){{/groovy}}{{/async}}
```
2. Use the object editor to add an object of type `XWiki.TemplateProviderClass` (named "Template Provider Class") to that document.
3. Go to another document you can view (can be the home page) and append `?sheet=XWiki.AdminTemplatesSheet` to the URL.

When the attack is successful, a template with name "Hello from groovy!" is displayed in the list while on fixed systems, the full title should be displayed.

### Patches

This vulnerability has been patched in XWiki 13.10.11, 14.4.8, 14.10.1 and 15.0 RC1.

### Workarounds

The vulnerability can be fixed by patching the code in the affected XWiki document as shown in the [patch](https://github.com/xwiki/xwiki-platform/commit/7bf7094f8ffac095f5d66809af7554c9cc44de09).

### References

* https://jira.xwiki.org/browse/XWIKI-20268
* https://github.com/xwiki/xwiki-platform/commit/7bf7094f8ffac095f5d66809af7554c9cc44de09

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)
