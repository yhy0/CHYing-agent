# XWiki Platform: Remote code execution from account via SearchSuggestSourceSheet

**GHSA**: GHSA-34fj-r5gq-7395 | **CVE**: CVE-2024-31465 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-search-ui** (maven): >= 5.2-milestone-2, < 14.10.20
- **org.xwiki.platform:xwiki-platform-search-ui** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.platform:xwiki-platform-search-ui** (maven): >= 15.6-rc-1, < 15.10-rc-1

## Description

### Impact
Any user with edit right on any page can execute any code on the server by adding an object of type `XWiki.SearchSuggestSourceClass` to their user profile or any other page. This compromises the confidentiality, integrity and availability of the whole XWiki installation.

To reproduce on an instance, as a user without script nor programming rights, add an object of type `XWiki.SearchSuggestSourceClass` to your profile page. On this object, set every possible property to `}}}{{async}}{{groovy}}println("Hello from Groovy!"){{/groovy}}{{/async}}` (i.e., name, engine, service, query, limit and icon). Save and display the page, then append `?sheet=XWiki.SearchSuggestSourceSheet` to the URL. If any property displays as `Hello from Groovy!}}}`, then the instance is vulnerable.

### Patches
This vulnerability has been patched in XWiki 14.10.20, 15.5.4 and 15.10 RC1.

### Workarounds
[This patch](https://github.com/xwiki/xwiki-platform/commit/6a7f19f6424036fce3d703413137adde950ae809#diff-67b473d2b6397d65b7726c6a13555850b11b10128321adf9e627e656e1d130a5) can be manually applied to the document `XWiki.SearchSuggestSourceSheet`.

### References
* https://jira.xwiki.org/browse/XWIKI-21474
* https://github.com/xwiki/xwiki-platform/commit/6a7f19f6424036fce3d703413137adde950ae809

