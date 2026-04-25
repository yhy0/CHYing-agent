# XWiki Platform remote code execution from account via custom skins support

**GHSA**: GHSA-cv55-v6rw-7r5v | **CVE**: CVE-2024-31987 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-862

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 6.4-milestone-1, < 14.10.19
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 15.6-rc-1, < 15.10-rc-1

## Description

### Impact
Any user who can edit any page like their profile can create a custom skin with a template override that is executed with programming right, thus allowing remote code execution. 

To reproduce, as a user without edit, script or admin right, add an object of class `XWiki.XWikiSkins` to your profile. Name it whatever you want and set the Base Skin to `flamingo`.
Add an object of class `XWikiSkinFileOverrideClass` and set the path to `macros.vm` and the content to:
```
#macro(mediumUserAvatar $username)
  #resizedUserAvatar($username 50)
  $services.logging.getLogger('Skin').error("I got programming: $services.security.authorization.hasAccess('programming')")
#end
```
Back to your profile, click `Test this skin`. Force a refresh, just in case.
If the error "Skin - I got programming: true" gets logged, the installation is vulnerable.

### Patches
This has been patched in XWiki 14.10.19, 15.5.4 and 15.10RC1.

### Workarounds
We're not aware of any workaround except upgrading.

### References
* https://jira.xwiki.org/browse/XWIKI-21478
* https://github.com/xwiki/xwiki-platform/commit/3d4dbb41f52d1a6e39835cfb1695ca6668605a39 (>= 15.8 RC1)
* https://github.com/xwiki/xwiki-platform/commit/da177c3c972e797d92c1a31e278f946012c41b56 (< 15.8 RC1)

