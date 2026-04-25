# gotortc vulnerable to Cross-Site Request Forgery

**GHSA**: GHSA-qgj8-g9q4-7f2p | **CVE**: CVE-2024-29192 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **github.com/AlexxIT/go2rtc** (go): < 1.9.0

## Description

gotortc is a camera streaming application. Versions 1.8.5 and prior are vulnerable to Cross-Site Request Forgery. The `/api/config` endpoint allows one to modify the existing configuration with user-supplied values. While the API is only allowing localhost to interact without authentication, an attacker may be able to achieve that depending on how go2rtc is set up on the upstream application, and given that this endpoint is not protected against CSRF, it allows requests from any origin (e.g. a "drive-by" attack) . The `exec` handler allows for any stream to execute arbitrary commands. An attacker may add a custom stream through `api/config`, which may lead to arbitrary command execution. In the event of a victim visiting the server in question, their browser will execute the requests against the go2rtc instance. Commit 8793c3636493c5efdda08f3b5ed5c6e1ea594fd9 adds a warning about secure API access.
