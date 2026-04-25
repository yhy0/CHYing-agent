# Improper Authentication in Capsule Proxy

**GHSA**: GHSA-9cwv-cppx-mqjm | **CVE**: CVE-2022-23652 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/clastix/capsule-proxy** (go): < 0.2.1

## Description

### Impact

Using a malicious `Connection` header, an attacker with a proper authentication mechanism could start a privilege escalation towards the Kubernetes API Server, being able to exploit the `cluster-admin` Role bound to `capsule-proxy`.

### Patches

Patch has been merged in the v0.2.1 release.

### Workarounds

Upgrading is mandatory.

