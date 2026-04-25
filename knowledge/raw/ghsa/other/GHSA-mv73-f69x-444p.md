# Go Fiber CSRF Token Validation Vulnerability

**GHSA**: GHSA-mv73-f69x-444p | **CVE**: CVE-2023-45141 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **github.com/gofiber/fiber/v2** (go): < 2.50.0

## Description

A Cross-Site Request Forgery (CSRF) vulnerability has been identified in the application, which allows an attacker to obtain tokens and forge malicious requests on behalf of a user. This can lead to unauthorized actions being taken on the user's behalf, potentially compromising the security and integrity of the application.

## Vulnerability Details

The vulnerability is caused by improper validation and enforcement of CSRF tokens within the application. The following issues were identified:

1. **Lack of Token Association**: The CSRF token was validated against tokens in storage but was not tied to the original requestor that generated it, allowing for token reuse.

## Remediation

To remediate this vulnerability, it is recommended to take the following actions:

1. **Update the Application**: Upgrade the application to a fixed version with a patch for the vulnerability.

2. **Implement Proper CSRF Protection**: Review the updated documentation and ensure your application's CSRF protection mechanisms follow best practices.

4. **Choose CSRF Protection Method**: Select the appropriate CSRF protection method based on your application's requirements, either the Double Submit Cookie method or the Synchronizer Token Pattern using sessions.

5. **Security Testing**: Conduct a thorough security assessment, including penetration testing, to identify and address any other security vulnerabilities.

## Defence-in-depth

Users should take additional security measures like captchas or Two-Factor Authentication (2FA) and set Session cookies with SameSite=Lax or SameSite=Strict, and the Secure and HttpOnly attributes.
