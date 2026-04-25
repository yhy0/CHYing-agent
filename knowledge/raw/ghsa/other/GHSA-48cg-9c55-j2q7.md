# hippo4j Includes Hard Coded Secret Key in JWT Creation

**GHSA**: GHSA-48cg-9c55-j2q7 | **CVE**: CVE-2025-51606 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-798

**Affected Packages**:
- **cn.hippo4j:hippo4j-core** (maven): >= 1.0.0, <= 1.5.0

## Description

hippo4j 1.0.0 to 1.5.0, uses a hard-coded secret key in its JWT (JSON Web Token) creation. This allows attackers with access to the source code or compiled binary to forge valid access tokens and impersonate any user, including privileged ones such as "admin". The vulnerability poses a critical security risk in systems where authentication and authorization rely on the integrity of JWTs.
