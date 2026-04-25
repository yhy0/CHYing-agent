# XWiki Platform vulnerable to privilege escalation from view right using Invitation.InvitationCommon

**GHSA**: GHSA-px54-3w5j-qjg9 | **CVE**: CVE-2023-29518 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 2.5-m-1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-invitation-ui** (maven): >= 14.5, < 14.10.1

## Description

### Impact
Any user with view rights can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of `Invitation.InvitationCommon`. This page is installed by default.

See https://jira.xwiki.org/browse/XWIKI-20283 for the reproduction steps.

### Patches
The vulnerability has been patched in XWiki 15.0-rc-1, 14.10.1, 14.4.8, and 13.10.11.

### Workarounds
The issue can be fixed by applying this [patch](https://github.com/xwiki/xwiki-platform/commit/3d055a0a5ec42fdebce4d71ee98f94553fdbfebf) on `Invitation.InvitationCommon`.

### References
- https://github.com/xwiki/xwiki-platform/commit/3d055a0a5ec42fdebce4d71ee98f94553fdbfebf
- https://jira.xwiki.org/browse/XWIKI-20283

### For more information

If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)
