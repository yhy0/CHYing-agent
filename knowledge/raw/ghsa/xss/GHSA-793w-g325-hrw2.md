# XWiki Platform vulnerable to persistent Cross-site Scripting through CKEditor Configuration pages

**GHSA**: GHSA-793w-g325-hrw2 | **CVE**: CVE-2023-36477 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-ckeditor-ui** (maven): >= 14.6-rc-1, < 14.10.6
- **org.xwiki.contrib:application-ckeditor-ui** (maven): >= 1.9, < 1.64.9
- **org.xwiki.platform:xwiki-platform-ckeditor-ui** (maven): >= 15.0-rc-1, < 15.1

## Description

### Effect
Any user with edit rights can edit all pages in the `CKEditor' space. This makes it possible to perform a variety of harmful actions, such as
- removing technical documents, leading to loss of service
- Editing the javascript configuration of CKEditor, leading to persistent XSS

### Patches
This issue has been patched in XWiki 14.10.6 and XWiki 15.1.
This issue has been patched on the CKEditor Integration extension 1.64.9 for XWiki version older than 14.6RC1.

### Workarounds
The issue can be fixed manually by restricting the `edit` and `delete` rights to a trusted user or group (e.g. the `XWiki.XWikiAdminGroup` group), implicitly disabling those rights for all other users.
See https://github.com/xwiki/xwiki-platform/commit/9d9d86179457cb8dc48b4491510537878800be4f

### References
- https://jira.xwiki.org/browse/XWIKI-20590
- https://jira.xwiki.org/browse/CKEDITOR-508
- https://github.com/xwiki/xwiki-platform/commit/9d9d86179457cb8dc48b4491510537878800be4f


### For more information

If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)
