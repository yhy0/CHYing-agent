# org.xwiki.platform:xwiki-platform-oldcore makes Incorrect Use of Privileged APIs with DocumentAuthors

**GHSA**: GHSA-pwfv-3cvg-9m4c | **CVE**: CVE-2023-29507 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-648

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 14.5, < 14.10
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 14.4.1, < 14.4.7

## Description

### Impact

The Document script API returns directly a DocumentAuthors allowing to set any authors to the document, which in consequence can allow subsequent executions of scripts since this author is used for checking rights. 
Example of such attack:

```
{{velocity}}
$doc.setContent('{{velocity}}$xcontext.context.authorReference{{/velocity}}')
$doc.authors.setContentAuthor('xwiki:XWiki.superadmin')
$doc.getRenderedContent()
{{/velocity}}
```

### Patches
The problem has been patched in XWiki 14.10 and 14.4.7 by returning a safe script API.

### Workarounds
There no easy workaround apart of upgrading. 

### References

  * https://jira.xwiki.org/browse/XWIKI-20380
  * https://github.com/xwiki/xwiki-platform/commit/905cdd7c421dbf8c565557cdc773ab1aa9028f83

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira](https://jira.xwiki.org)
* Email us at [security ML](mailto:security@xwiki.org)
