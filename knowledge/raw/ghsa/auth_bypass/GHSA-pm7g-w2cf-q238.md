# pac4j-jwt: JwtAuthenticator Authentication Bypass via JWE-Wrapped PlainJWT

**GHSA**: GHSA-pm7g-w2cf-q238 | **CVE**: CVE-2026-29000 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-347

**Affected Packages**:
- **org.pac4j:pac4j-jwt** (maven): >= 6.0.4.1, < 6.3.3
- **org.pac4j:pac4j-jwt** (maven): >= 5.0.0-RC1, < 5.7.9
- **org.pac4j:pac4j-jwt** (maven): < 4.5.9

## Description

pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.
