# Apache SeaTunnel Web Authentication vulnerability

**GHSA**: GHSA-cp2c-x2pc-fph7 | **CVE**: CVE-2023-48396 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-290

**Affected Packages**:
- **org.apache.seatunnel:seatunnel-web** (maven): < 1.0.1

## Description

Web Authentication vulnerability in Apache SeaTunnel. Since the jwt key is hardcoded in the application, an attacker can forge any token to log in any user.

Attacker can get secret key in /seatunnel-server/seatunnel-app/src/main/resources/application.yml and then create a token. This issue affects Apache SeaTunnel: 1.0.0.

Users are recommended to upgrade to version 1.0.1, which fixes the issue.
