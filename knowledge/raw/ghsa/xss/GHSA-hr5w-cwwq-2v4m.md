# ZITADEL's Improper Content-Type Validation Leads to Account Takeover via Stored XSS + CSP Bypass

**GHSA**: GHSA-hr5w-cwwq-2v4m | **CVE**: CVE-2024-29891 | **Severity**: high (CVSS 8.7)

**CWE**: CWE-79, CWE-434

**Affected Packages**:
- **github.com/zitadel/zitadel** (go): < 2.42.17
- **github.com/zitadel/zitadel** (go): >= 2.43.0, < 2.43.11
- **github.com/zitadel/zitadel** (go): >= 2.44.0, < 2.44.7
- **github.com/zitadel/zitadel** (go): >= 2.45.0, < 2.45.5
- **github.com/zitadel/zitadel** (go): >= 2.46.0, < 2.46.5
- **github.com/zitadel/zitadel** (go): >= 2.47.0, < 2.47.8
- **github.com/zitadel/zitadel** (go): >= 2.48.0, < 2.48.3

## Description

### Impact

ZITADEL users can upload their own avatar image and various image types are allowed.

Due to a missing check, an attacker could upload HTML and pretend it is an image to gain access to the victim's account in certain scenarios.
A possible victim would need to directly open the supposed image in the browser, where a session in ZITADEL needs to be active for this exploit to work.

The exploit could only be reproduced if the victim was using Firefox. Chrome, Safari as well as Edge did not execute the code.

### Patches

2.x versions are fixed on >= [2.48.3](https://github.com/zitadel/zitadel/releases/tag/v2.48.3)
2.47.x versions are fixed on >= [2.47.8](https://github.com/zitadel/zitadel/releases/tag/v2.47.8)
2.46.x versions are fixed on >= [2.46.5](https://github.com/zitadel/zitadel/releases/tag/v2.46.5)
2.45.x versions are fixed on >= [2.45.5](https://github.com/zitadel/zitadel/releases/tag/v2.45.5)
2.44.x versions are fixed on >= [2.44.7](https://github.com/zitadel/zitadel/releases/tag/v2.44.7)
2.43.x versions are fixed on >= [2.43.11](https://github.com/zitadel/zitadel/releases/tag/v2.43.11)
2.42.x versions are fixed on >= [2.42.17](https://github.com/zitadel/zitadel/releases/tag/v2.42.17)

ZITADEL recommends upgrading to the latest versions available in due course.

### Workarounds

There is no workaround since a patch is already available.

### References

None

### Questions

If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

### Credits

Thanks to Amit Laish – GE Vernova for finding and reporting the vulnerability.

