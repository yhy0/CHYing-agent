# Improper Restriction of Excessive Authentication Attempts in Argo API

**GHSA**: GHSA-xcqr-9h24-vrgw | **CVE**: CVE-2020-8827 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-307

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): < 1.5.1

## Description

As of v1.5.0, the Argo API does not implement anti-automation measures such as rate limiting, account lockouts, or other anti-bruteforce measures. Attackers can submit an unlimited number of authentication attempts without consequence.

### Specific Go Packages Affected
github.com/argoproj/argo-cd/util/cache
