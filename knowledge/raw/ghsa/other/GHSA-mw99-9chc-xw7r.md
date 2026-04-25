# Maliciously crafted Git server replies can cause DoS on go-git clients

**GHSA**: GHSA-mw99-9chc-xw7r | **CVE**: CVE-2023-49568 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20

**Affected Packages**:
- **github.com/go-git/go-git/v5** (go): < 5.11.0
- **gopkg.in/src-d/go-git.v4** (go): >= 4.7.1, <= 4.13.1

## Description

### Impact
A denial of service (DoS) vulnerability was discovered in go-git versions prior to `v5.11`. This vulnerability allows an attacker to perform denial of service attacks by providing specially crafted responses from a Git server which triggers resource exhaustion in `go-git` clients. 

Applications using only the in-memory filesystem supported by `go-git` are not affected by this vulnerability.
This is a `go-git` implementation issue and does not affect the upstream `git` cli.

### Patches
Users running versions of `go-git` from `v4` and above are recommended to upgrade to `v5.11` in order to mitigate this vulnerability.

### Workarounds
In cases where a bump to the latest version of `go-git` is not possible, we recommend limiting its use to only trust-worthy Git servers.

## Credit
Thanks to Ionut Lalu for responsibly disclosing this vulnerability to us.

### References
- [GHSA-mw99-9chc-xw7r](https://github.com/go-git/go-git/security/advisories/GHSA-mw99-9chc-xw7r)

