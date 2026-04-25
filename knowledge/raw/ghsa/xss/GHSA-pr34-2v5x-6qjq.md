# ZITADEL has 1-Click Account Takeover via XSS in /saml-post Endpoint

**GHSA**: GHSA-pr34-2v5x-6qjq | **CVE**: CVE-2026-29191 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/zitadel/zitadel** (go): >= 4.0.0, < 4.12.0
- **github.com/zitadel/zitadel/v2** (go): >= 4.0.0, < 4.12.0

## Description

### Summary

A vulnerability was discovered in Zitadel's login V2 interface that allowed a possible account takeover.

### Impact

Zitadel exposes an HTTP endpoint named /saml-post. This endpoint is used for handling requests to SAML IdPs and accepts two HTTP GET parameters: url and id. When these parameters are supplied, users’ browsers auto-submit an HTTP POST request to the provided url parameter.
 
The endpoint insecurely redirects users using the provided url GET parameter. As a result, by specifying a javascript: scheme, malicious JS code could be executed on Zitadel users’ browsers. 

The endpoint also reflects user-supplied input in the server response, without HTML-encoding it. As a result, it is possible to inject arbitrary HTML code, which again leads to malicious JS code execution in the Zitadel users’ browsers.

An unauthenticated remote attacker can exploit these XSS vulnerabilities, and thus, execute malicious JavaScript code on behalf of Zitadel users. By doing so, such an attacker could reset the password of their victims, and take over their accounts.

It's important to note that this specific attack vector is mitigated for accounts that have Multi-Factor Authentication (MFA) or Passwordless authentication enabled.

### Affected Versions

Systems running one of the following versions are affected:
- **4.x**: `4.0.0` through `4.11.1` (including RC versions)
 
Important Note: Although this /saml-post endpoint is used when Zitadel is integrated with a SAML Identity Provider (IdP), the vulnerability in this finding does not require Zitadel to be configured with a SAML IdP. Consequently, Zitadel is vulnerable in its default, out-of-the-box configuration.

### Patches

The vulnerability has been addressed in the latest releases. The patch reworked the integration of SAML IdPs and the /saml-post endpoint no longer exists. Additionally, the page to change the password, now always requires the user's current password regardless of the state of the authenticated session.

4.x: Upgrade to >= [4.12.0](https://github.com/zitadel/zitadel/releases/tag/v4.12.0)

### Workarounds

The recommended solution is to upgrade to a patched version. If an upgrade is not possible and no SAML IdP integration is needed, a WAF or reverse proxy rule can be deployed to prevent access to the endpoint.

### Questions

If there are any questions or comments about this advisory, please email them to [security@zitadel.com](mailto:security@zitadel.com)

### Credits

ZITADEL extends thanks once again to Amit Laish from GE Vernova for finding and reporting the vulnerability.
