# Authentication Bypass in github.com/russellhaering/gosaml2

**GHSA**: GHSA-xhqq-x44f-9fgg | **CVE**: CVE-2020-29509 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-115

**Affected Packages**:
- **github.com/russellhaering/gosaml2** (go): < 0.6.0

## Description

### Impact
Given a valid SAML Response, it may be possible for an attacker to mutate the XML document in such a way that gosaml2 will trust a different portion of the document than was signed.

Depending on the implementation of the Service Provider this enables a variety of attacks, including users accessing accounts other than the one to which they authenticated in the Identity Provider, or full authentication bypass.

### Patches
Service Providers utilizing gosaml2 should upgrade to v0.6.0 or greater.
