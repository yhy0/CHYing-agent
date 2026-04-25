# XWiki Platform vulnerable to  reflected cross-site scripting through revision parameter in content menu

**GHSA**: GHSA-j9rc-w3wv-fv62 | **CVE**: CVE-2023-46732 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-79, CWE-80

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 9.7-rc-1, < 14.10.14
- **org.xwiki.platform:xwiki-platform-flamingo-skin-resources** (maven): >= 15.0-rc-1, < 15.5.1

## Description

### Impact

XWiki is vulnerable to reflected cross-site scripting (RXSS) via the `rev` parameter that is used in the content of the content menu without escaping. If an attacker can convince a user to visit a link with a crafted parameter, this allows the attacker to execute arbitrary actions in the name of the user, including remote code (Groovy) execution in the case of a user with programming right, compromising the confidentiality, integrity and availability of the whole XWiki installation.

The vulnerability can be demonstrated by opening `<xwiki-host>/xwiki/bin/view/Main/?rev=xar%3Aorg.xwiki.platform%3Axwiki-platform-distribution-flavor-common%2F15.5%25%25%22%3e%3cscript%3ealert(1)%3c%2fscript%3e` where `<xwiki-host>` is the URL of your XWiki installation. If an alert is displayed, the installation is vulnerable.

### Patches
This has been patched in XWiki 15.6 RC1, 15.5.1 and 14.10.14.

### Workarounds
The [patch](https://github.com/xwiki/xwiki-platform/commit/04e325d57d4bcb6ab79bddcafbb19032474c2a55) can be manually applied without upgrading (or restarting) the instance.

### References
* https://jira.xwiki.org/browse/XWIKI-21095
* https://github.com/xwiki/xwiki-platform/commit/04e325d57d4bcb6ab79bddcafbb19032474c2a55

### Attribution

We thank Agostino Parentela, Vulnerability Management Engineer of TicketOne S.p.A., [agostino.parentela@ticketone.it](mailto:agostino.parentela@ticketone.it) for reporting this vulnerability.
