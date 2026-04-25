# org.xwiki.platform:xwiki-platform-attachment-api vulnerable to Missing Authorization on Attachment Move

**GHSA**: GHSA-rwwx-6572-mp29 | **CVE**: CVE-2023-37910 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-862

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-attachment-api** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-attachment-api** (maven): >= 14.5, < 14.10.4

## Description

### Impact

An attacker with edit access on any document (can be the user profile which is editable by default) can move any attachment of any other document to this attacker-controlled document. This allows the attacker to access and possibly publish any attachment of which the name is known, regardless if the attacker has view or edit rights on the source document of this attachment. Further, the attachment is deleted from the source document. This vulnerability exists since the introduction of attachment move support in XWiki 14.0 RC1.

### Patches

This vulnerability has been patched in XWiki 14.4.8, 14.10.4, and 15.0 RC1.

### Workarounds

There is no workaround apart from upgrading to a fixed version.

### References

* https://jira.xwiki.org/browse/XWIKI-20334
* https://github.com/xwiki/xwiki-platform/commit/d7720219d60d7201c696c3196c9d4a86d0881325

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

This vulnerability has been reported on Intigriti by [Mete](https://www.linkedin.com/in/metehan-kalkan-5a3201199).
