# Remote code execution/programming rights with configuration section from any user account

**GHSA**: GHSA-qj86-p74r-7wp5 | **CVE**: CVE-2023-50723 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 2.3, < 14.10.15
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 15.0-rc-1, < 15.5.2
- **org.xwiki.platform:xwiki-platform-administration-ui** (maven): >= 15.6-rc-1, < 15.7-rc-1

## Description

### Impact

Anyone who can edit an arbitrary wiki page in an XWiki installation can gain programming right through several cases of missing escaping in the code for displaying sections in the administration interface. This impacts the confidentiality, integrity and availability of the whole XWiki installation. Normally, all users are allowed to edit their own user profile so this should be exploitable by all users of the XWiki instance.

The easiest way to reproduce this is to edit any document with the object editor and add an object of type `XWiki.ConfigurableClass` ("Custom configurable sections"). Set "Display in section" and "Display in Category" to "other", set scope to "Wiki and all spaces" and "Heading" to `{{async}}{{groovy}}services.logging.getLogger("attacker").error("Attack from Heading succeeded!"); println("Hello from Groovy!"){{/groovy}}{{/async}}`. Click "Save". Open `<xwiki-host>/xwiki/bin/view/Main/?sheet=XWiki.AdminSheet&viewer=content&editor=globaladmin&section=other` where `<xwiki-host>` is the URL of your XWiki installation. If this displays just "Hello from Groovy!" in a heading and generates an error message with content "Attack from Heading succeeded!" in XWiki's log, the attack succeeded. Similar attacks are also possible by creating this kind of object on a document with a specially crafted name, see the referenced Jira issues for more reproduction steps.

### Patches
This has been fixed in XWiki 14.10.15, 15.5.2 and 15.7RC1

### Workarounds

It is possible to manually apply the fixes for the vulnerability by editing two pages in the wiki. [This patch](https://github.com/xwiki/xwiki-platform/commit/bd82be936c21b65dee367d558e3050b9b6995713#diff-0c8db1bc71d4e1508c0667050741827551ba130f324b3213352bc4a67645f648) needs to be applied to the page `XWiki.ConfigurableClassMacros`. Further, the following patches need to be applied to the page `XWiki.ConfigurableClass`:

* https://github.com/xwiki/xwiki-platform/commit/749f6aee1bfbcf191c3734ea0aa9eba3aa63240e#diff-bf419a99140f3c12fd78ea30f855b63cfb74c1c976ff4436898266d9b37ad3ce
* https://github.com/xwiki/xwiki-platform/commit/1157c1ecea395aac7f64cd8a6f484b1225416dc7#diff-bf419a99140f3c12fd78ea30f855b63cfb74c1c976ff4436898266d9b37ad3ce
* https://github.com/xwiki/xwiki-platform/commit/0f367aaae4e0696f61cf5a67a75edd27d1d16db6

Note that also the page `XWiki.ConfigurableClass` needs to be changed to `xwiki/2.1` syntax for the escaping to work properly but the security vulnerability is fixed also without changing the syntax.

### References

* https://github.com/xwiki/xwiki-platform/commit/bd82be936c21b65dee367d558e3050b9b6995713
* https://github.com/xwiki/xwiki-platform/commit/749f6aee1bfbcf191c3734ea0aa9eba3aa63240e
* https://github.com/xwiki/xwiki-platform/commit/1157c1ecea395aac7f64cd8a6f484b1225416dc7
* https://github.com/xwiki/xwiki-platform/commit/0f367aaae4e0696f61cf5a67a75edd27d1d16db6
* https://jira.xwiki.org/browse/XWIKI-21122
* https://jira.xwiki.org/browse/XWIKI-21121
* https://jira.xwiki.org/browse/XWIKI-21194
