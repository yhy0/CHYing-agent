# Privilege escalation (PR)/RCE from account through class sheet

**GHSA**: GHSA-36fm-j33w-c25f | **CVE**: CVE-2023-32069 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-863

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-test-ui** (maven): >= 3.3-milestone-3, < 14.10.4

## Description

### Impact

It's possible for a user to execute anything with the right of the author of the XWiki.ClassSheet document.

**Steps to Reproduce:**

1. Edit your user profile with the object editor and add an object of type `DocumentSheetBinding` with value `Default Class Sheet`
1. Edit your user profile with the wiki editor and add the syntax `{{async}}{{groovy}}println("Hello " + "from groovy!"){{/groovy}}{{/async}}`
1. Click "Save & View"

**Expected result:**

An error is displayed as the user doesn't have the right to execute the Groovy macro.

**Actual result:**

The text "Hello from groovy!" is displayed at the top of the document.

### Patches

This has been patched in XWiki 15.0-rc-1 and 14.10.4.

### Workarounds

There are no known workarounds for it.

### References

https://jira.xwiki.org/browse/XWIKI-20566
https://github.com/xwiki/xwiki-platform/commit/de72760d4a3e1e9be64a10660a0c19e9534e2ec4

### For more information
If you have any questions or comments about this advisory:
*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)
