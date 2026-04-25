# Spring Security authorization bypass for method security annotations on private methods

**GHSA**: GHSA-9pp5-9c7g-4r83 | **CVE**: CVE-2025-41232 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-693

**Affected Packages**:
- **org.springframework.security:spring-security-aspects** (maven): >= 6.4.0, < 6.4.6
- **org.springframework.security:spring-security-core** (maven): >= 6.4.0, < 6.4.6

## Description

Spring Security Aspects may not correctly locate method security annotations on private methods. This can cause an authorization bypass.

Your application may be affected by this if the following are true:

  *  You are using @EnableMethodSecurity(mode=ASPECTJ) and spring-security-aspects, and
  *  You have Spring Security method annotations on a private method
In that case, the target method may be able to be invoked without proper authorization.

You are not affected if:

  *  You are not using @EnableMethodSecurity(mode=ASPECTJ) or spring-security-aspects, or
  *  You have no Spring Security-annotated private methods
