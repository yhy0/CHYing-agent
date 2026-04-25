# org.xwiki.platform:xwiki-platform-panels-ui Eval Injection vulnerability

**GHSA**: GHSA-qx9h-c5v6-ghqh | **CVE**: CVE-2023-29214 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-panels-ui** (maven): >= 1.1-M2, < 13.10.11
- **org.xwiki.platform:xwiki-platform-panels-ui** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-panels-ui** (maven): >= 14.5, < 14.10

## Description

### Impact
Any user with edit rights can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the included pages in the IncludedDocuments panel.

**Precondition**: As an admin, add the `Panels.IncludedDocuments` panel on one column.

A proof of concept exploit is to edit a document and add the following code before saving.

```
{{display reference="{{cache~}~}{{groovy~}~}println(~"Hello from Groovy~" + ~" in included document!~"){{/groovy~}~}{{/cache~}~}"/}}
```

**expected**
The right had side panels contain:
```
One included page: 
{{cache}}{{groovy}}println("Hello from Groovy" + " in included document!"){{/groovy}}{{/cache}}
```

**actual**
The right had side panels contain:
```
One included page:
    XWiki.Hello from Groovy in included document!
```

### Patches
The problem has been patched on XWiki 14.4.7, and 14.10.

### Workarounds
The issue can be fixed manually applying this [patch](https://github.com/xwiki/xwiki-platform/commit/50b4d91418b4150933f0317eb4a94ceaf5b69f67).

### References
- https://github.com/xwiki/xwiki-platform/commit/50b4d91418b4150933f0317eb4a94ceaf5b69f67
- https://jira.xwiki.org/browse/XWIKI-20306

### For more information
If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)

