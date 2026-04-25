# Traefik affected by Go oauth2/jws Improper Validation of Syntactic Correctness of Input vulnerability

**GHSA**: GHSA-3wqc-mwfx-672p | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-1286

**Affected Packages**:
- **github.com/traefik/traefik/v3** (go): < 3.3.6
- **github.com/traefik/traefik/v2** (go): < 2.11.24
- **github.com/traefik/traefik/v3** (go): = 3.4.0-rc1

## Description

### Summary
We have encountered a security vulnerability being reported by our scanners for Traefik 2.11.22.
- https://security.snyk.io/vuln/SNYK-CHAINGUARDLATEST-TRAEFIK33-9403297

### Details
It seems to target oauth2/jws library.

### PoC
No steps to replicate this vulnerability

### Impact
We have a strict control on security and we always try to stay up-to-date with the fixes received for third-party solutions.

## Patches

- https://github.com/traefik/traefik/releases/tag/v2.11.24
- https://github.com/traefik/traefik/releases/tag/v3.3.6
- https://github.com/traefik/traefik/releases/tag/v3.4.0-rc2
