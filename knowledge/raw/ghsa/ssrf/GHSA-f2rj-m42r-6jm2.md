# Skipper vulnerable to SSRF via X-Skipper-Proxy

**GHSA**: GHSA-f2rj-m42r-6jm2 | **CVE**: CVE-2022-38580 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/zalando/skipper** (go): < 0.13.237

## Description

### Impact

Skipper prior to version v0.13.236 is vulnerable to server-side request forgery (SSRF). An attacker can exploit a vulnerable version of proxy to access the internal metadata server or other unauthenticated URLs by adding an specific header (X-Skipper-Proxy) to the http request.

### Patches
The problem was patched in version https://github.com/zalando/skipper/releases/tag/v0.13.237.
Users need to upgrade to skipper `>=v0.13.237`.

### Workarounds

Use `dropRequestHeader("X-Skipper-Proxy")` filter

### References

https://github.com/zalando/skipper/releases/tag/v0.13.237

### For more information
If you have any questions or comments about this advisory:

* Open an issue in https://github.com/zalando/skipper/issues/new/choose
* Chat with us in slack: https://app.slack.com/client/T029RQSE6/C82Q5JNH5
