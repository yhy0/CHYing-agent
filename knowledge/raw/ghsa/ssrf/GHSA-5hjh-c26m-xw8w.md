# ProxyScotch is vulnerable to a server-side Request Forgery (SSRF)

**GHSA**: GHSA-5hjh-c26m-xw8w | **CVE**: CVE-2022-25850 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/hoppscotch/proxyscotch** (go): < 1.0.0

## Description

ProxyScotch is a simple proxy server created for hoppscotch.io. The package github.com/hoppscotch/proxyscotch before 1.0.0 are vulnerable to Server-side Request Forgery (SSRF) when interceptor mode is set to proxy. It occurs when an HTTP request is made by a backend server to an untrusted URL submitted by a user. It leads to a leakage of sensitive information from the server.
