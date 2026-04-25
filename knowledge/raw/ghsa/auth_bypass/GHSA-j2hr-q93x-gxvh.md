# SSOReady has an XML Signature Bypass via differential XML parsing

**GHSA**: GHSA-j2hr-q93x-gxvh | **CVE**: CVE-2024-47832 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-347

**Affected Packages**:
- **github.com/ssoready/ssoready** (go): < 0.0.0-20241009153838-7f92a0630439

## Description

Affected versions are vulnerable to XML signature bypass attacks. An attacker can carry out signature bypass if you have access to certain IDP-signed messages. The underlying mechanism exploits differential behavior between XML parsers.

Users of https://ssoready.com, the public hosted instance of SSOReady, are unaffected. We advise folks who self-host SSOReady to upgrade to 7f92a06 or later. Do so by updating your SSOReady Docker images from `sha-...` to `sha-7f92a06`. The documentation for self-hosting SSOReady is available [here](https://ssoready.com/docs/self-hosting/self-hosting-sso-ready).

Vulnerability was discovered by @ahacker1-securesaml. It's likely the precise mechanism of attack affects other SAML implementations, so the reporter and I (@ucarion) have agreed to not disclose it in detail publicly at this time.
