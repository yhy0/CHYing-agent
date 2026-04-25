# XWiki Platform privilege escalation (PR)/RCE from account through Invitation subject/message

**GHSA**: GHSA-7954-6m9q-gpvf | **CVE**: CVE-2023-37914 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 2.5-m-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 14.5, < 14.10.6
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 15.0-rc-1, < 15.2-rc-1

## Description

### Impact
Any user who can view `Invitation.WebHome` can execute arbitrary script macros including Groovy and Python macros that allow remote code execution including unrestricted read and write access to all wiki contents. This can be reproduced with the following steps:


1.    Open the invitation application (Invitation.WebHome).
1.    Set the subject to `{{cache}}{{groovy}}new File("/tmp/exploit.txt").withWriter { out -> out.println("Attacked from invitation!"); }{{/groovy}}{{/cache}}`
1.    Click "Preview"


### Patches
The vulnerability has been patched on XWiki 14.4.8, 15.2-rc-1, and 14.10.6.

### Workarounds
The vulnerability can be patched manually by applying the [patch](https://github.com/xwiki/xwiki-platform/commit/ff1d8a1790c6ee534c6a4478360a06efeb2d3591) on `Invitation.InvitationCommon` and `Invitation.InvitationConfig`.

### References
- https://jira.xwiki.org/browse/XWIKI-20421
- https://github.com/xwiki/xwiki-platform/commit/ff1d8a1790c6ee534c6a4478360a06efeb2d3591

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

