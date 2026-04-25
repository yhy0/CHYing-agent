# XWiki programming rights may be inherited by inclusion

**GHSA**: GHSA-qcj3-wpgm-qpxh | **CVE**: CVE-2024-38369 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-863

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-rendering-macro-include** (maven): < 15.0-rc-1

## Description

### Impact

The content of a document included using `{{include reference="targetdocument"/}}` is executed with the right of the includer and not with the right of its author.

This means that any user able to modify the target document can impersonate the author of the content which used the `include` macro.

### Patches

This has been patched in XWiki 15.0 RC1 by making the default behavior safe.

### Workarounds

Make sure to protect any included document to make sure only allowed users can modify it.

A workaround have been provided in 14.10.2 to allow forcing to execute the included content with the target content author instead of the default behavior. See https://extensions.xwiki.org/xwiki/bin/view/Extension/Include%20Macro#HAuthor for more details.

### References

https://jira.xwiki.org/browse/XWIKI-5027
https://jira.xwiki.org/browse/XWIKI-20471

### For more information
If you have any questions or comments about this advisory:
*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)

