# org.xwiki.platform:xwiki-platform-office-importer vulnerable to arbitrary server side file writing from account through office converter

**GHSA**: GHSA-vcvr-v426-3m3m | **CVE**: CVE-2023-37913 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-office-importer** (maven): >= 3.5-milestone-1, < 14.10.8
- **org.xwiki.platform:xwiki-platform-office-importer** (maven): >= 15.0-rc-1, < 15.3-rc-1

## Description

### Impact

Triggering the office converter with a specially crafted file name allows writing the attachment's content to an attacker-controlled location on the server as long as the Java process has write access to that location. In particular in the combination with attachment moving, a feature introduced in XWiki 14.0, this is easy to reproduce but it also possible to reproduce in versions as old as XWiki 3.5 by uploading the attachment through the REST API which doesn't remove `/` or `\` from the filename. As the mime type of the attachment doesn't matter for the exploitation, this could e.g., be used to replace the `jar`-file of an extension which would allow executing arbitrary Java code and thus impact the confidentiality, integrity and availability of the XWiki installation. To reproduce the issue on versions since XWiki 14.0, execute the following steps:

1.  Activate the office server
2.  Upload an arbitrary file with the extension .doc, e.g., to your user profile (you can use a regular plain text file, only the extension matters).
3.  Use the attachment move feature to rename the file to ../../../../../tmp/Hello from XWiki.txt where the latter part is the location of a file you want to write on the server. The number of ../ depends on the directory depth, the provided example should work on Linux with the demo distribution.
4.  Click the "preview" link to trigger the office converter

For information how to reproduce on older versions, see the [Jira issue](https://jira.xwiki.org/browse/XWIKI-20715).

To the best of our knowledge, this attack is not possible when the office conversion process doesn't run as the code fails before the file is written.

### Patches

This vulnerability has been patched in XWiki 14.10.8 and 15.3RC1.

### Workarounds

There are no known workarounds apart from disabling the office converter.

### References

* https://jira.xwiki.org/browse/XWIKI-20715
* https://github.com/xwiki/xwiki-platform/commit/45d182a4141ff22f3ff289cf71e4669bdc714544
