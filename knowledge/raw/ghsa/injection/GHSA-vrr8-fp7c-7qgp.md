# org.xwiki.platform:xwiki-platform-flamingo-theme-ui vulnerable to privilege escalation

**GHSA**: GHSA-vrr8-fp7c-7qgp | **CVE**: CVE-2023-30537 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-flamingo-theme-ui** (maven): >= 12.6.6, < 13.10.11
- **org.xwiki.platform:xwiki-platform-flamingo-theme-ui** (maven): >= 14.0-rc-1, < 14.4.7
- **org.xwiki.platform:xwiki-platform-flamingo-theme-ui** (maven): >= 14.5, < 14.10

## Description

### Impact

Any user with the right to add an object on a page can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the XWiki installation. The root cause is improper escaping of the styles properties `FlamingoThemesCode.WebHome`. This page is installed by default.

#### Reproduction Steps

**Steps to reproduce**:

- As a user without script or programming rights, edit your user profile with the object editor (enable advanced mode if necessary to get access) and add an object of type "Theme Class" of "FlamingoThemesCode". In the field "body-bg" (all other fields should work, too) add the following text:

`{{/html}} {{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("Hello " + "from groovy!"){{/groovy}}{{/async}}`

- Click "Save & View"
- Open <xwiki-host>/xwiki/bin/view/FlamingoThemesCode/WebHomeSheet where <xwiki-host> is the URL of your XWiki installation

**Expected result**:

The list of color themes either doesn't include the user's profile or displays a regular preview.

**Actual result**:

The user's profile is listed as color theme but instead of the little preview the message

```
Failed to execute the [html] macro. Cause: [When using HTML content inline, you can only use inline HTML content. Block HTML content (such as tables) cannot be displayed. Try leaving an empty line before and after the macro.]. Click on this message for details.
Hello from groovy!">
```

is displayed. This shows that a Groovy macro with content created by the user has been executed and thus demonstrates a privilege escalation from simple user account to programming rights.


### Patches
The vulnerability has been patched in XWiki 13.10.11, 14.4.7 and 14.10.

### Workarounds
The issue can be fixed by applying this [patch](https://github.com/xwiki/xwiki-platform/commit/df596f15368342236f8899ca122af8f3df0fe2e8#diff-e2153fa59f9d92ef67b0afbf27984bd17170921a3b558fac227160003d0dfd2a) on `FlamingoThemesCode.WebHomeSheet`.

### References
- patch: https://github.com/xwiki/xwiki-platform/commit/df596f15368342236f8899ca122af8f3df0fe2e8
- Jira: https://jira.xwiki.org/browse/XWIKI-20280

### For more information
If you have any questions or comments about this advisory:

*    Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
*    Email us at [Security Mailing List](mailto:security@xwiki.org)
