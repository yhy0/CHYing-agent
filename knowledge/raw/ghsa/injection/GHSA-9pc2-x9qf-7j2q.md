# org.xwiki.platform:xwiki-platform-legacy-notification-activitymacro Eval Injection vulnerability

**GHSA**: GHSA-9pc2-x9qf-7j2q | **CVE**: CVE-2023-29209 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-legacy-notification-activitymacro** (maven): >= 10.9, < 13.10.11
- **org.xwiki.platform:xwiki-platform-legacy-notification-activitymacro** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-legacy-notification-activitymacro** (maven): >= 14.5, < 14.10

## Description

### Impact

Any user with view rights on commonly accessible documents including the legacy notification activity macro can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the macro parameters of the [legacy notification activity macro](https://extensions.xwiki.org/xwiki/bin/view/Extension/Legacy%20Notification%20Activity%20Macro/). This macro is installed by default in XWiki.

A proof of concept exploit is

```
{{activity wikis="~" /~}~} {{async async=~"true~" cached=~"false~" context=~"doc.reference~"~}~}{{groovy~}~}println(~"Hello from Groovy!~"){{/groovy~}~}"/}}
```

If the output of this macro is
```
The [notifications] macro is a standalone macro and it cannot be used inline. Click on this message for details.
Hello from Groovy!"    displayMinorEvents="false" displayRSSLink="false" /}}
```
or similar, the XWiki installation is vulnerable. The vulnerability can be exploited via every wiki page that is editable including the user's profile, but also with just view rights using the HTMLConverter that is part of the [CKEditor integration](https://extensions.xwiki.org/xwiki/bin/view/Extension/CKEditor%20Integration/) which is bundled with XWiki.

### Patches
The vulnerability has been patched in XWiki 13.10.11, 14.4.7 and 14.10.

### Workarounds
The issue can be fixed by replacing the code of the legacy notification activity macro by the [patched version](https://github.com/xwiki/xwiki-platform/commit/94392490884635c028199275db059a4f471e57bc). Alternatively, if the macro isn't used, the document `XWiki.Notifications.Code.Legacy.ActivityMacro` can also be completely deleted.

### References
* https://github.com/xwiki/xwiki-platform/commit/94392490884635c028199275db059a4f471e57bc
* https://jira.xwiki.org/browse/XWIKI-20258

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

