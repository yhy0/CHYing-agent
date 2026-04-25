# XWiki Platform: Remote code execution from edit in multilingual wikis via translations

**GHSA**: GHSA-xxp2-9c9g-7wmj | **CVE**: CVE-2024-31983 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-862

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-localization-source-wiki** (maven): >= 4.3-milestone-2, < 14.10.20
- **org.xwiki.platform:xwiki-platform-localization-source-wiki** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.platform:xwiki-platform-localization-source-wiki** (maven): >= 15.6-rc-1, < 15.10-rc-1

## Description

### Impact

In multilingual wikis, translations can be edited by any user who has edit right, circumventing the rights that are normally required for authoring translations (script right for user-scope translations, wiki admin for translations on the wiki). This can be exploited for remote code execution if the translation value is not properly escaped where it is used. To reproduce, in a multilingual wiki, as a user without script or admin right, edit a translation of `AppWithinMinutes.Translations` and in the line `platform.appwithinminutes.description=`  add `{{async}}{{groovy}}println("Hello from Translation"){{/groovy}}{{/async}}` at the end. Then open the app with in minutes home page (`AppWithinMinutes.WebHome`) in the same locale. If translations are still working and "Hello from Translation" is displayed at the end of the introduction, the installation is vulnerable.

### Patches
This has been patched in XWiki 14.10.20, 15.5.4 and 15.10RC1.

### Workarounds
We're not aware of any workaround except restricting edit right on documents that contain translations.

### References
* https://jira.xwiki.org/browse/XWIKI-21411
* https://github.com/xwiki/xwiki-platform/commit/c4c8d61c30de72298d805ccc82df2a307f131c54

