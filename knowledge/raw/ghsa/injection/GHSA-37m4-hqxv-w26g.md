# XWiki Platform CSRF remote code execution through scheduler job's document reference

**GHSA**: GHSA-37m4-hqxv-w26g | **CVE**: CVE-2024-31986 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-95, CWE-352

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-scheduler-ui** (maven): >= 3.1, < 14.10.19
- **org.xwiki.platform:xwiki-platform-scheduler-ui** (maven): >= 15.0-rc-1, < 15.5.4
- **org.xwiki.platform:xwiki-platform-scheduler-ui** (maven): >= 15.6-rc-1, < 15.9

## Description

### Impact
By creating a document with a special crafted documented reference and an `XWiki.SchedulerJobClass` XObject, it is possible to execute arbitrary code on the server whenever an admin visits the scheduler page or the scheduler page is referenced, e.g., via an image in a comment on a page in the wiki.

To reproduce on an XWiki installation, click on this link to create a new document : `<xwiki-host>/xwiki/bin/view/%22%3E%5D%5D%7B%7B%2Fhtml%7D%7D%7B%7Basync%20context%3D%22request/parameters%22%7D%7D%7B%7Bvelocity%7D%7D%23evaluate%28%24request/eval%29/`.
Then, add to this document an object of type `XWiki.SchedulerJobClass`.
Finally, as an admin, go to  `<xwiki-host>/xwiki/bin/view/Scheduler/?eval=$services.logging.getLogger(%22attacker%22).error(%22Hello%20from%20URL%20Parameter!%20I%20got%20programming:%20$services.security.authorization.hasAccess(%27programming%27)%22)`.
If the logs contain `ERROR attacker - Hello from URL Parameter! I got programming: true`, the installation is vulnerable.

### Patches
The vulnerability has been fixed on XWiki 14.10.19, 15.5.5, and 15.9.

### Workarounds
Modify the Scheduler.WebHome page following this [patch](https://github.com/xwiki/xwiki-platform/commit/f16ca4ef1513f84ce2e685d4a05d689bd3a2ab4c#diff-1e2995eacccbbbdcc4987ff64f46ac74837d166cf9e92920b4a4f8af0f10bd47).

### References
- https://jira.xwiki.org/browse/XWIKI-21416
- https://github.com/xwiki/xwiki-platform/commit/f16ca4ef1513f84ce2e685d4a05d689bd3a2ab4c

