# Quarkus HTTP vulnerable to incorrect evaluation of permissions

**GHSA**: GHSA-4f4r-wgv2-jjvg | **CVE**: CVE-2023-4853 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-148, CWE-863

**Affected Packages**:
- **io.quarkus:quarkus-vertx-http** (maven): < 2.16.11.Final
- **io.quarkus:quarkus-vertx-http** (maven): >= 3.0.0, < 3.2.6.Final
- **io.quarkus:quarkus-vertx-http** (maven): >= 3.3.0, < 3.3.3
- **io.quarkus:quarkus-undertow** (maven): < 2.16.11.Final
- **io.quarkus:quarkus-undertow** (maven): >= 3.0.0, < 3.2.6.Final
- **io.quarkus:quarkus-undertow** (maven): >= 3.3.0, < 3.3.3
- **io.quarkus:quarkus-csrf-reactive** (maven): < 2.16.11.Final
- **io.quarkus:quarkus-csrf-reactive** (maven): >= 3.0.0, < 3.2.6.Final
- **io.quarkus:quarkus-csrf-reactive** (maven): >= 3.3.0, < 3.3.3
- **io.quarkus:quarkus-keycloak-authorization** (maven): < 2.16.11.Final
- **io.quarkus:quarkus-keycloak-authorization** (maven): >= 3.0.0, < 3.2.6.Final
- **io.quarkus:quarkus-keycloak-authorization** (maven): >= 3.3.0, < 3.3.3

## Description

A flaw was found in Quarkus where HTTP security policies are not sanitizing certain character permutations correctly when accepting requests, resulting in incorrect evaluation of permissions. This issue could allow an attacker to bypass the security policy altogether, resulting in unauthorized endpoint access and possibly a denial of service.
