# org.xwiki.contrib.markdown:syntax-markdown-commonmark12 vulnerable to XSS via Markdown content

**GHSA**: GHSA-8g2j-rhfh-hq3r | **CVE**: CVE-2025-46558 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.contrib.markdown:syntax-markdown-commonmark12** (maven): >= 8.2, < 8.9

## Description

### Impact
The Markdown syntax is vulnerable to XSS through HTML. In particular, using Markdown syntax, it's possible for any user to embed Javascript code that will then be executed on the browser of any other user visiting either the document or the comment that contains it. In the instance that this code is executed by a user with admins or programming rights, this issue compromises the confidentiality, integrity and availability of the whole XWiki installation.

To reproduce, on an instance where the CommonMark Markdown Syntax 1.2 extension is installed, log in as a user without script rights. Edit a document and set its syntax to Markdown. Then , add the content `<script>alert("XSS")</script>` and refresh the page. If an alert appears containing "XSS", then the instance is vulnerable.

### Patches
This has been patched in version 8.9 of the CommonMark Markdown Syntax 1.2 extension.

### Workarounds
We're not aware of any workaround except upgrading.

### References
* https://jira.xwiki.org/browse/MARKDOWN-80
* https://github.com/xwiki-contrib/syntax-markdown/commit/d136472d6e8a47981a0ede420a9096f88ffa5035
