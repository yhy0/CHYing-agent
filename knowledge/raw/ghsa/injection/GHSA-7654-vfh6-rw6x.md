# Remote code execution from account through SearchAdmin

**GHSA**: GHSA-7654-vfh6-rw6x | **CVE**: CVE-2023-50721 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-search-ui** (maven): >= 4.5-rc-1, < 14.10.15
- **org.xwiki.platform:xwiki-platform-search-ui** (maven): >= 15.0-rc-1, < 15.5.2
- **org.xwiki.platform:xwiki-platform-search-ui** (maven): >= 15.6-rc-1, < 15.7-rc-1

## Description

### Impact
The search administration interface doesn't properly escape the id and label of search user interface extensions, allowing the injection of XWiki syntax containing script macros including Groovy macros that allow remote code execution, impacting the confidentiality, integrity and availability of the whole XWiki instance. This attack can be executed by any user who can edit some wiki page like the user's profile (editable by default) as user interface extensions that will be displayed in the search administration can be added on any document by any user.

To reproduce, edit any document with the object editor, add an object of type `XWiki.UIExtensionClass`, set "Extension Point Id" to `org.xwiki.platform.search`, set "Extension ID" to `{{async}}{{groovy}}services.logging.getLogger("attacker").error("Attack from extension id succeeded!"){{/groovy}}{{/async}}`, set "Extension Parameters" to `label={{async}}{{groovy}}services.logging.getLogger("attacker").error("Attack from label succeeded!"){{/groovy}}{{/async}}` and "Extension Scope" to "Current User". Then open the page `XWiki.SearchAdmin`, e.g., on http://localhost:8080/xwiki/bin/view/XWiki/SearchAdmin. If there are error log messages in XWiki's log that announce that attacks succeeded, the instance is vulnerable.


### Patches
The necessary escaping has been added in XWiki 14.10.15, 15.5.2 and 15.7RC1.

### Workarounds
The [patch](https://github.com/xwiki/xwiki-platform/commit/62863736d78ffd60d822279c5fb7fb9593042766#diff-2272c913e5ca43813e52f8fa748c9b043bf0f01561908d7eba6ca3601d8475c4) can be manually applied to the page `XWiki.SearchAdmin`.

### References
* https://github.com/xwiki/xwiki-platform/commit/62863736d78ffd60d822279c5fb7fb9593042766
* https://jira.xwiki.org/browse/XWIKI-21200
