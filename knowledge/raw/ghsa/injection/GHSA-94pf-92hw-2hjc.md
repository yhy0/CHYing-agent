# XWiki Platform vulnerable to  Code injection through NotificationRSSService

**GHSA**: GHSA-94pf-92hw-2hjc | **CVE**: CVE-2023-36469 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-74

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-notifications-ui** (maven): >= 9.6-rc-1, < 14.10.6
- **org.xwiki.platform:xwiki-platform-notifications-ui** (maven): >= 15.0-rc-1, < 15.2-rc-1

## Description

### Impact

Any user who can edit their own user profile and notification settings can execute arbitrary script macros including Groovy and Python macros that allow remote code execution including unrestricted read and write access to all wiki contents. This can be reproduced with the following steps:

1. Login as a user without script or programming right.
2. Go to the notifications preferences in your user profile.
3. Disable the "Own Events Filter" and enable notifications in the notification menu for "Like".
4. Set your first name to `{{cache id="security" timeToLive="1"}}{{groovy}}println("Hello from groovy!"){{/groovy}}{{/cache}}`
5. Click on the like button at the bottom left of the user profile.
6. Click on the notifications bell in the top bar and then on "RSS Feed".

If the text "Profile of Hello from groovy!" and/or "liked by Hello from groovy!" is displayed, the attack succeeded. The expected result would have been that the entered first name is displayed as-is in the description of the feed.

### Patches
This has been patched in XWiki 14.10.6 and 15.2RC1.

### Workarounds
The main security fix can be manually applied by patching the affected document `XWiki.Notifications.Code.NotificationRSSService` as shown in the [patch](https://github.com/xwiki/xwiki-platform/commit/217e5bb7a657f2991b154a16ef4d5ae9c29ad39c#diff-7221a548809fa2ba34348556f4b5bd436463c559ebdf691197932ee7ce4478ca). This will break the link to the differences, though as this requires additional changes to Velocity templates as shown in the patch. While the [default](https://github.com/xwiki/xwiki-platform/commit/217e5bb7a657f2991b154a16ef4d5ae9c29ad39c#diff-b261c6eac3108c3e6e734054c28a78f59d3439ab72fe8582dadf87670a0d15a4) template is available in the instance and can be easily patched, the template for mentions is contained in a `.jar`-file and thus cannot be fixed without replacing that jar.

### References
* https://jira.xwiki.org/browse/XWIKI-20610
* https://github.com/xwiki/xwiki-platform/commit/217e5bb7a657f2991b154a16ef4d5ae9c29ad39c

