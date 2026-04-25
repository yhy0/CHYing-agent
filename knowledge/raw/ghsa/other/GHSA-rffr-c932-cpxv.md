# Cross-site Request Forgery (CSRF) in Cloud Native Computing Foundation Harbor

**GHSA**: GHSA-rffr-c932-cpxv | **CVE**: CVE-2019-19025 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-352

**Affected Packages**:
- **github.com/goharbor/harbor** (go): >= 1.7.0, < 1.8.6
- **github.com/goharbor/harbor** (go): >= 1.9.0, < 1.9.3

## Description

Cure53 has discovered that the Harbor web interface does not implement protection mechanisms against Cross-Site Request Forgery (CSRF). By luring an authenticated user onto a prepared third-party website, an attacker can execute any action on the platform in the context of the currently authenticated victim.

The vulnerability was immediately fixed by the Harbor team and all supported versions were patched.

Successful exploitation of this issue will lead to 3rd parties executing actions on the platform of behalf of authenticated users and administrators.

If your product uses the affected releases of Harbor, update to version 1.8.6 and 1.9.3 to patch this issue immediately.

https://github.com/goharbor/harbor/releases/tag/v1.8.6
https://github.com/goharbor/harbor/releases/tag/v1.9.3
