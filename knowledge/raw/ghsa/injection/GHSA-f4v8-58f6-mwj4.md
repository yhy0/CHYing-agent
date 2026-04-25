# org.xwiki.platform:xwiki-platform-flamingo-theme-ui Eval Injection vulnerability

**GHSA**: GHSA-f4v8-58f6-mwj4 | **CVE**: CVE-2023-29509 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-theme-ui** (maven): >= 7.2-rc-1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-flamingo-theme-ui** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-flamingo-theme-ui** (maven): >= 14.5, < 14.10

## Description

### Impact
Any user with view rights on commonly accessible documents can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the `documentTree` macro parameters in  This macro is installed by default in `FlamingoThemesCode.WebHome`. This page is installed by default.

Example of reproduction:
Open `<xwiki_host>/xwiki/bin/view/%22%20%2F%7D%7D%20%7B%7Basync%20async%3D%22true%22%20cached%3D%22false%22%20context%3D%22doc.reference%22%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22Hello%20%22%20%2B%20%22from%20groovy!%22)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D?sheet=FlamingoThemesCode.WebHome&xpage=view` where `<xwiki_host>` is the URL of your XWiki installation.

> The [documentTree] macro is a standalone macro and it cannot be used inline. Click on this message for details.
> Hello from groovy!.WebHome" /}}

is displayed. This shows that the Groovy macro that is passed in the URL has been executed and thus demonstrates a privilege escalation from view to programming rights.

### Patches
The vulnerability has been patched in XWiki 13.10.11, 14.4.7 and 14.10.

### Workarounds
The issue can be fixed by replacing the code of `FlamingoThemesCode.WebHome` by the [patched version](https://github.com/xwiki/xwiki-platform/commit/80d5be36f700adcd56b6c8eb3ed8b973f62ec0ae).

### References
- https://jira.xwiki.org/browse/XWIKI-20279
- https://github.com/xwiki/xwiki-platform/commit/80d5be36f700adcd56b6c8eb3ed8b973f62ec0ae

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

