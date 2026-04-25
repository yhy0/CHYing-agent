# XWiki Platform vulnerable to code injection in display method used in user profiles

**GHSA**: GHSA-x764-ff8r-9hpx | **CVE**: CVE-2023-29523 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 3.3-milestone-1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 14.0-rc-1, < 14.4.8
- **org.xwiki.platform:xwiki-platform-oldcore** (maven): >= 14.5, < 14.10.2

## Description

### Impact

Any user who can edit their own user profile can execute arbitrary script macros including Groovy and Python macros that allow remote code execution including unrestricted read and write access to all wiki contents. The following syntax, to be put, e.g., in the about section of the user profile, demonstrates a proof of concept:

```
{{html wiki="true"}}~{~{~/~h~t~m~l~}~}~ ~{~{~c~a~c~h~e~}~}~{~{~g~r~o~o~v~y~}~}~p~r~i~n~t~l~n~(~1~)~{~{~/~g~r~o~o~v~y~}~}~{~{~/~c~a~c~h~e~}~}~{{/html}}
```

While it would be expected that the above code is displayed just without the `~`, in fact just "1" is displayed, followed by a lot of raw HTML code. The same vulnerability can also be exploited in other contexts where the `display` method on a document is used to display a field with wiki syntax, for example in applications created using [App Within Minutes](https://extensions.xwiki.org/xwiki/bin/view/Extension/App%20Within%20Minutes%20Application).

### Patches
This has been patched in XWiki 13.10.11, 14.4.8, 14.10.2 and 15.0RC1.

### Workarounds
There is no workaround apart from upgrading.

### References
* https://jira.xwiki.org/browse/XWIKI-20327
* https://github.com/xwiki/xwiki-platform/commit/0d547181389f7941e53291af940966413823f61c

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

