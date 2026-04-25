# XWiki Platform XSS vulnerability from account in the create page form via template provider

**GHSA**: GHSA-gr82-8fj2-ggc3 | **CVE**: CVE-2023-45134 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): < 14.10.12
- **org.xwiki.platform:xwiki-platform-web-templates** (maven): >= 15.0-rc-1, < 15.5-rc-1
- **org.xwiki.platform:xwiki-web-standard** (maven): >= 2.4-milestone-2, < 3.1-milestone-1
- **org.xwiki.platform:xwiki-platform-web** (maven): >= 3.1-milestone-1, < 13.4-rc-1

## Description

### Impact
An attacker can create a template provider on any document that is part of the wiki (could be the attacker's user profile) that contains malicious code. This code is executed when this template provider is selected during document creation which can be triggered by sending the user to a URL. For the attacker, the only requirement is to have an account as by default the own user profile is editable. This allows an attacker to execute arbitrary actions with the rights of the user opening the malicious link. Depending on the rights of the user, this may allow remote code execution and full read and write access to the whole XWiki installation.

For reproduction, the following steps can be used:
1. As a simple user with no script right, edit the user profile with the object editor and add an object of type "Template Provider Class". Set the name to "My Template", set template to any page on the wiki. In "Creation Restrictions", enter `<img onerror="alert(1)" src="https://www.example.com"`. Accept the suggestion to add this string in the dropdown. Click "Save & View"
2. As any user with edit right, open `<xwiki-host>/xwiki/bin/create/Main/WebHome?parent=&templateprovider=XWiki.<username>&name=foo&spaceReference=Bar`, where `<xwiki-host>` is the URL of your XWiki installation and `<username>` is the username of the attacker.

If an alert is displayed, the installation is vulnerable.

### Patches
This has been patched in XWiki 14.10.12 and 15.5RC1 by adding the appropriate escaping.

### Workarounds
The vulnerable template file createinline.vm is part of XWiki's WAR and can be patched by manually applying the [changes from the fix](https://github.com/xwiki/xwiki-platform/commit/ba56fda175156dd35035f2b8c86cbd8ef1f90c2e#diff-c222148bddebe4ff7629350f4053b618504a4ab172e697938c8fddf7c1fc6bc8).

### References
* https://github.com/xwiki/xwiki-platform/commit/ba56fda175156dd35035f2b8c86cbd8ef1f90c2e
* https://jira.xwiki.org/browse/XWIKI-20962
