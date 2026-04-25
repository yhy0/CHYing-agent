# XWiki Remote Code Execution Vulnerability via User Registration

**GHSA**: GHSA-rj7p-xjv7-7229 | **CVE**: CVE-2024-21650 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 2.2, < 14.10.17
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 15.0-rc-1, < 15.5.3
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 15.6-rc-1, < 15.8-rc-1

## Description

### Impact
XWiki is vulnerable to a remote code execution (RCE) attack through its user registration feature. This issue allows an attacker to execute arbitrary code by crafting malicious payloads in the "first name" or "last name" fields during user registration. This impacts all installations that have user registration enabled for guests.

To reproduce, register with any username and password and the following payload as "first name": `]]{{/html}}{{async}}{{groovy}}services.logging.getLogger("attacker").error("Attack succeeded){{/groovy}}{{/async}}`. In the following page that confirms the success of the registration, the full first name should be displayed, linking to the created user. If the formatting is broken and a log message with content "ERROR attacker - Attack succeeded!" is logged, the attack succeeded.

### Patches
This vulnerability has been patched in XWiki 14.10.17, 15.5.3 and 15.8 RC1.

### Workarounds

In the administration of your wiki, under "Users & Rights" > "Registration" set the "Registration Successful Message" to the following code:

```velocity
#set($message = $services.localization.render('core.register.successful', 'xwiki/2.1', ['USERLINK', $userName]))
#set($userLink = $xwiki.getUserName("$userSpace$userName"))
{{info}}$message.replace('USERLINK', "{{html clean=false}}$userLink{{/html}}"){{/info}}
```

### References
* https://jira.xwiki.org/browse/XWIKI-21173
* https://github.com/xwiki/xwiki-platform/commit/b290bfd573c6f7db6cc15a88dd4111d9fcad0d31
