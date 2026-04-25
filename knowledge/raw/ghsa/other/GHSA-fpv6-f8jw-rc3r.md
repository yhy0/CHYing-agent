# Elvish vulnerable to remote code execution via the web UI backend

**GHSA**: GHSA-fpv6-f8jw-rc3r | **CVE**: CVE-2021-41088 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-346, CWE-668

**Affected Packages**:
- **github.com/elves/elvish** (go): < 0.14.0

## Description

### Impact

Elvish's backend for the experimental web UI (started by `elvish -web`) hosts an endpoint that allows executing the code sent from the web UI.

The backend does not check the origin of requests correctly. As a result, if the user has the web UI backend open and visits a compromised or malicious website, the website can send arbitrary code to the endpoint in localhost.

### Patches

All Elvish releases since 0.14.0 no longer include the experimental web UI, although it is still possible for the user to build a version from source that includes it.

The issue can be patched for previous versions by removing the web UI (found in web, pkg/web or pkg/prog/web, depending on the exact version).

### Workarounds

Do not use the experimental web UI.

### For more information

If you have any questions or comments about this advisory, please email xiaqqaix@gmail.com.
