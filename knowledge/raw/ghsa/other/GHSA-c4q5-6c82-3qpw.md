# Spring Security vulnerable to Authorization Bypass of Static Resources in WebFlux Applications

**GHSA**: GHSA-c4q5-6c82-3qpw | **CVE**: CVE-2024-38821 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-285, CWE-770

**Affected Packages**:
- **org.springframework.security:spring-security-web** (maven): < 5.7.13
- **org.springframework.security:spring-security-web** (maven): >= 5.8.0, < 5.8.15
- **org.springframework.security:spring-security-web** (maven): >= 6.2.0, < 6.2.7
- **org.springframework.security:spring-security-web** (maven): >= 6.0.0, < 6.0.13
- **org.springframework.security:spring-security-web** (maven): >= 6.1.0, < 6.1.11
- **org.springframework.security:spring-security-web** (maven): >= 6.3.0, < 6.3.4

## Description

Spring WebFlux applications that have Spring Security authorization rules on static resources can be bypassed under certain circumstances.

For this to impact an application, all of the following must be true:

  *  It must be a WebFlux application
  *  It must be using Spring's static resources support
  *  It must have a non-permitAll authorization rule applied to the static resources support
