# Atlantis Events vulnerable to Timing Attack

**GHSA**: GHSA-jxqv-jcvh-7gr4 | **CVE**: CVE-2022-24912 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-203, CWE-208

**Affected Packages**:
- **github.com/runatlantis/atlantis** (go): < 0.19.7

## Description

The package github.com/runatlantis/atlantis/server/controllers/events before 0.19.7 is vulnerable to Timing Attack in the webhook event validator code, which does not use a constant-time comparison function to validate the webhook secret. It can allow an attacker to recover this secret as an attacker and then forge webhook events.
