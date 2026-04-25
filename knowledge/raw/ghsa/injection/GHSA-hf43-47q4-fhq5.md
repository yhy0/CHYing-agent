# XWiki Commons missing escaping of `{` in Velocity escapetool allows remote code execution

**GHSA**: GHSA-hf43-47q4-fhq5 | **CVE**: CVE-2024-31996 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.commons:xwiki-commons-velocity** (maven): >= 3.0.1, < 14.10.19
- **org.xwiki.commons:xwiki-commons-velocity** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.commons:xwiki-commons-velocity** (maven): >= 15.6-rc-1, < 15.9-rc-1

## Description

### Impact
The HTML escaping of escaping tool that is used in XWiki doesn't escape `{`, which, when used in certain places, allows XWiki syntax injection and thereby remote code execution.

To reproduce in an XWiki installation, open `<xwiki-host>/xwiki/bin/view/Panels/PanelLayoutUpdate?place=%7B%7B%2Fhtml%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bvelocity%7D%7D%23evaluate(%24request.eval)%7B%7B%2Fvelocity%7D%7D%7B%7B%2Fasync%7D%7D&eval=Hello%20from%20URL%20Parameter!%20I%20got%20programming%3A%20%24services.security.authorization.hasAccess(%27programming%27)` where `<xwiki-host>` is the URL of your XWiki installation. If this displays `You are not admin on this place Hello from URL Parameter! I got programming: true`, the installation is vulnerable.

### Patches
The vulnerability has been fixed on XWiki 14.10.19, 15.5.5, and 15.9 RC1.

### Workarounds
Apart from upgrading, there is no generic workaround. However, replacing `$escapetool.html` by `$escapetool.xml` in XWiki documents fixes the vulnerability. In a standard XWiki installation, we're only aware of the document `Panels.PanelLayoutUpdate` that exposes this vulnerability, patching this document is thus a workaround. Any extension could expose this vulnerability and might thus require patching, too.

### References
- https://github.com/xwiki/xwiki-commons/commit/b94142e2a66ec32e89eacab67c3da8d91f5ef93a
- https://jira.xwiki.org/browse/XCOMMONS-2828
- https://jira.xwiki.org/browse/XWIKI-21438
