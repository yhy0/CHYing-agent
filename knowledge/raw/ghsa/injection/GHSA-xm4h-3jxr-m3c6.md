# XWiki Platform: Remote code execution through space title and Solr space facet

**GHSA**: GHSA-xm4h-3jxr-m3c6 | **CVE**: CVE-2024-31984 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-search-solr-ui** (maven): >= 7.2-rc-1, < 14.10.20
- **org.xwiki.platform:xwiki-platform-search-solr-ui** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.platform:xwiki-platform-search-solr-ui** (maven): >= 15.6-rc-1, < 15.10-rc-1

## Description

### Impact
By creating a document with a specially crafted title, it is possible to trigger remote code execution in the (Solr-based) search in XWiki. This allows any user who can edit the title of a space (all users by default) to execute any Groovy code in the XWiki installation which compromises the confidentiality, integrity and availability of the whole XWiki installation.

To reproduce, as a user without script nor programming rights, create a document with title `{{/html}}{{async}}{{groovy}}println("Hello from Groovy Title!"){{/groovy}}{{/async}}` and content `Test Document`. Using the search UI, search for `"Test Document"`, then deploy the `Location` facet on the right of the screen, next to the search results. The installation is vulnerable if you see an item such as:
```
Hello from Groovy Title!
</a>
<div class="itemCount">1</div>
</li>
</ul>
{{/html}}
```

### Patches
This has been patched in XWiki 14.10.20, 15.5.4 and 15.10 RC1.

### Workarounds
Modify the `Main.SolrSpaceFacet` page following this [patch](https://github.com/xwiki/xwiki-platform/commit/acba74c149a041345b24dcca52c586f872ba97fb#diff-22dd1949ed9019a39f2550f5a953a1a967c30a374dc9eeddb74069bf229b17d5).

### References
* https://jira.xwiki.org/browse/XWIKI-21471
* https://github.com/xwiki/xwiki-platform/commit/acba74c149a041345b24dcca52c586f872ba97fb
* https://github.com/xwiki/xwiki-platform/commit/74e301c481e69eeea674dac7fed6af3614cf08c5

