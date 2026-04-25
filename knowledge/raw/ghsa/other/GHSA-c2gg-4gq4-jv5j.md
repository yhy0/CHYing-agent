# XWiki Platform remote code execution from account through UIExtension parameters

**GHSA**: GHSA-c2gg-4gq4-jv5j | **CVE**: CVE-2024-31997 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-862

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-uiextension-api** (maven): < 14.10.19
- **org.xwiki.platform:xwiki-platform-uiextension-api** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.platform:xwiki-platform-uiextension-api** (maven): >= 15.6-rc-1, < 15.9-rc-1

## Description

### Impact
Parameters of UI extensions are always interpreted as Velocity code and executed with programming rights. Any user with edit right on any document like the user's own profile can create UI extensions. This allows remote code execution and thereby impacts the confidentiality, integrity and availability of the whole XWiki installation.

To reproduce, edit your user profile with the object editor and add a UIExtension object with the following values:
```
Extension Point ID: org.xwiki.platform.panels.Applications
Extension ID: platform.panels.myFakeApplication
Extension parameters: 
label=I got programming right: $services.security.authorization.hasAccess('programming')
target=Main.WebHome
targetQueryString=
icon=icon:bomb
Extension Scope: "Current User".
```

Save the document and open any document. If an application entry with the text "I got programming right: true" is displayed, the attack succeeded, if the code in "label" is displayed literally, the XWiki installation isn't vulnerable.

### Patches
This vulnerability has been patched in XWiki 14.10.19, 15.5.4 and 15.9-RC1.

### Workarounds
We're not aware of any workarounds apart from upgrading.

### References
* https://jira.xwiki.org/browse/XWIKI-21335
* https://github.com/xwiki/xwiki-platform/commit/171e7c7d0e56deaa7b3678657ae26ef95379b1ea

