# User Registration Bypass in Zitadel

**GHSA**: GHSA-3rmw-76m6-4gjc | **CVE**: CVE-2024-49757 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/zitadel/zitadel** (go): >= 2.63.0, < 2.63.5
- **github.com/zitadel/zitadel** (go): >= 2.62.0, < 2.62.7
- **github.com/zitadel/zitadel** (go): >= 2.61.0, < 2.61.4
- **github.com/zitadel/zitadel** (go): >= 2.60.0, < 2.60.4
- **github.com/zitadel/zitadel** (go): >= 2.59.0, < 2.59.5
- **github.com/zitadel/zitadel** (go): < 2.58.7

## Description

### Impact
Zitadel allows administrators to disable the user self-registration. Due to a missing security check in versions prior to 2.63.4, disabling the "User Registration allowed" option only hid the registration button on the login page. Users could bypass this restriction by directly accessing the registration URL (/ui/login/loginname) and register a user that way.

### Patches

2.x versions are fixed on >= [2.64.0](https://github.com/zitadel/zitadel/releases/tag/v2.64.0)
2.63.x versions are fixed on >= [2.63.5](https://github.com/zitadel/zitadel/releases/tag/v2.63.5)
2.62.x versions are fixed on >= [2.62.7](https://github.com/zitadel/zitadel/releases/tag/v2.62.7)
2.61.x versions are fixed on >= [2.61.4](https://github.com/zitadel/zitadel/releases/tag/v2.61.4)
2.60.x versions are fixed on >= [2.60.4](https://github.com/zitadel/zitadel/releases/tag/v2.60.4)
2.59.x versions are fixed on >= [2.59.5](https://github.com/zitadel/zitadel/releases/tag/v2.59.5)
2.58.x versions are fixed on >= [2.58.7](https://github.com/zitadel/zitadel/releases/tag/v2.58.7)

### Workarounds
Updating to the patched version is the recommended solution.

### Questions
If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

### Credits
Thanks to @sevensolutions and @evilgensec for disclosing this!

