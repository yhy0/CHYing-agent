# go-git clients vulnerable to DoS via maliciously crafted Git server replies

**GHSA**: GHSA-r9px-m959-cxf4 | **CVE**: CVE-2025-21614 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20, CWE-400, CWE-770

**Affected Packages**:
- **gopkg.in/src-d/go-git.v4** (go): >= 4.0.0, <= 4.13.1
- **github.com/go-git/go-git/v5** (go): < 5.13.0
- **github.com/go-git/go-git** (go): >= 4.0.0, <= 4.13.1

## Description

### Impact
A denial of service (DoS) vulnerability was discovered in go-git versions prior to `v5.13`. This vulnerability allows an attacker to perform denial of service attacks by providing specially crafted responses from a Git server which triggers resource exhaustion in `go-git` clients. 

This is a `go-git` implementation issue and does not affect the upstream `git` cli.

### Patches
Users running versions of `go-git` from `v4` and above are recommended to upgrade to `v5.13` in order to mitigate this vulnerability.

### Workarounds
In cases where a bump to the latest version of `go-git` is not possible, we recommend limiting its use to only trust-worthy Git servers.

## Credit
Thanks to Ionut Lalu for responsibly disclosing this vulnerability to us.
