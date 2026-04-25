# XWiki Platform vulnerable to privilege escalation (PR) from account through TipsPanel

**GHSA**: GHSA-h7cw-44vp-jq7h | **CVE**: CVE-2023-35166 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-863

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-help-ui** (maven): >= 8.1-milestone-1, < 14.10.5
- **org.xwiki.platform:xwiki-platform-help-ui** (maven): >= 15.0-rc-1, < 15.1-rc-1

## Description

### Impact

It's possible to execute any wiki content with the right of the TipsPanel author by creating a tip UI extension.

To reproduce:
* Add an object of type UIExtensionClass
* Set "Extension Point ID" to org.xwiki.platform.help.tipsPanel
* Set "Extension ID" to org.xwiki.platform.user.test (needs to be unique but otherwise doesn't matter)
* Set "Extension Parameters" to
    ```
    tip={{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("Hello " + "from groovy!"){{/groovy}}{{/async}}
    ```
* Set "Extension Scope" to "Current User".
* Click "Save & View"
* Open the "Help.TipsPanel" document at <xwiki-host>/xwiki/bin/view/Help/TipsPanel where <xwiki-host> is the URL of your XWiki installation and press refresh repeatedly.

The groovy macro is executed, after the fix you get an error instead.

### Patches

This has been patched in XWiki 15.1-rc-1 and 14.10.5.

### Workarounds

There are no known workarounds for it.

### References

* https://jira.xwiki.org/browse/XWIKI-20281
* https://github.com/xwiki/xwiki-platform/commit/98208c5bb1e8cdf3ff1ac35d8b3d1cb3c28b3263#diff-4e3467d2ef3871a68b2f910e67cf84531751b32e0126321be83c0f1ed5d90b29L176-R178

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)
