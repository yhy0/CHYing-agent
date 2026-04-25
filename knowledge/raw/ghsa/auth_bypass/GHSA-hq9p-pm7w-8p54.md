# pgjdbc Client Allows Fallback to Insecure Authentication Despite channelBinding=require Configuration

**GHSA**: GHSA-hq9p-pm7w-8p54 | **CVE**: CVE-2025-49146 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-287

**Affected Packages**:
- **org.postgresql:postgresql** (maven): >= 42.7.4, < 42.7.7

## Description

### Impact
When the PostgreSQL JDBC driver is configured with channel binding set to `required` (default value is `prefer`), the driver would incorrectly allow connections to proceed with authentication methods that do not support channel binding (such as password, MD5, GSS, or SSPI  authentication). This could allow a man-in-the-middle attacker to intercept connections that users believed were protected by channel binding requirements.

### Patches
TBD

### Workarounds

Configure `sslMode=verify-full` to prevent MITM attacks.

### References

* https://www.postgresql.org/docs/current/sasl-authentication.html#SASL-SCRAM-SHA-256
* https://datatracker.ietf.org/doc/html/rfc7677
* https://datatracker.ietf.org/doc/html/rfc5802
