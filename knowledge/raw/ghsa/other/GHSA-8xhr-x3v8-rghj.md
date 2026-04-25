# XWiki Platform's Groovy jobs check the wrong author, allowing remote code execution

**GHSA**: GHSA-8xhr-x3v8-rghj | **CVE**: CVE-2023-40573 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-284

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-scheduler-api** (maven): < 14.10.9
- **com.xpn.xwiki.platform.plugins:xwiki-plugin-scheduler** (maven): >= 1.3
- **org.xwiki.platform:xwiki-platform-scheduler-api** (maven): >= 15.0-rc-1, < 15.4-rc-1

## Description

### Impact

XWiki supports scheduled jobs that contain Groovy scripts. Currently, the job checks the content author of the job for programming right. However, modifying or adding a job script to a document doesn't modify the content author. Together with a CSRF vulnerability in the job scheduler, this can be exploited for remote code execution by an attacker with edit right on the wiki.

For successful exploitation, the needs to have edit right on a document whose content has last been changed by a user with programming right. This could be the user profile for users created by admins. In this document, the attacker can create an object of class `XWiki.SchedulerJobClass` using the object editor. By setting job class to `com.xpn.xwiki.plugin.scheduler.GroovyJob`, cron expression to `0 0/5 * * * ?` and job script to `services.logging.getLogger("foo").error("Job content executed")`, the attacker can create a job. Now this job just needs to be triggered or scheduled. This can be achieved by embedding an image with the following XWiki syntax in any document that is visited by an admin: `[[image:path:/xwiki/bin/view/Scheduler/?do=trigger&which=Attacker.Document]]` where `Attacker.Document` is the document that has been prepared by the attacker. If the attack is successful, an error log entry with "Job content executed" will be produced.

### Patches
This vulnerability has been patched in XWiki 14.10.9 and 15.4RC1.

### Workarounds
There is no workaround.

### References
* https://jira.xwiki.org/browse/XWIKI-20852
* https://github.com/xwiki/xwiki-platform/commit/fcdcfed3fe2e8a3cad66ae0610795a2d58ab9662
