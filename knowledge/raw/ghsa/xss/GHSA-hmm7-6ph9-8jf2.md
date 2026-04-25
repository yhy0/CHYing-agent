# org.xwiki.platform:xwiki-platform-livedata-macro vulnerable to Basic Cross-site Scripting

**GHSA**: GHSA-hmm7-6ph9-8jf2 | **CVE**: CVE-2023-29508 | **Severity**: high (CVSS 8.9)

**CWE**: CWE-79, CWE-80

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-livedata-macro** (maven): >= 13.10.10, < 13.10.11
- **org.xwiki.platform:xwiki-platform-livedata-macro** (maven): >= 14.4, < 14.4.7
- **org.xwiki.platform:xwiki-platform-livedata-macro** (maven): >= 14.9, < 14.10

## Description

### Impact
A user without script rights can introduce a stored XSS by using the Live Data macro, if the last author of the content of the page has script rights.

For instance, by adding the LiveData below in the about section of the profile of a user created by an admin.

```javascript
{{liveData id="movies" properties="title,description"}}
{
  "data": {
    "count": 1,
    "entries": [
      {
        "title": "Meet John Doe",
        "url": "https://www.imdb.com/title/tt0033891/",
        "description": "<img onerror='alert(1)' src='foo' />"
      }
    ]
  },
  "meta": {
    "propertyDescriptors": [
      {
        "id": "title",
        "name": "Title",
        "visible": true,
        "displayer": {"id": "link", "propertyHref": "url"}
      },
      {
        "id": "description",
        "name": "Description",
        "visible": true,
        "displayer": "html"
      }
    ]
  }
}
{{/liveData}}
```

### Patches
This has been patched in XWiki 14.10, 14.4.7, and 13.10.11.

### Workarounds
No known workaround.

### References
- https://jira.xwiki.org/browse/XWIKI-20312

### For more information
If you have any questions or comments about this advisory:

* Open an issue in [Jira](http://jira.xwiki.org/)
* Email us at [Security ML](mailto:security@xwiki.org)
