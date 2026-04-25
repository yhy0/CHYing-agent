# Spring Boot Security Bypass with Wildcard Pattern Matching on Cloud Foundry

**GHSA**: GHSA-g5h3-w546-pj7f | **CVE**: CVE-2023-20873 | **Severity**: critical (CVSS 9.8)

**CWE**: N/A

**Affected Packages**:
- **org.springframework.boot:spring-boot-actuator-autoconfigure** (maven): >= 3.0.0, < 3.0.6
- **org.springframework.boot:spring-boot-actuator-autoconfigure** (maven): >= 2.7.0, < 2.7.11
- **org.springframework.boot:spring-boot-actuator-autoconfigure** (maven): >= 2.6.0, < 2.6.15
- **org.springframework.boot:spring-boot-actuator-autoconfigure** (maven): < 2.5.15

## Description

In Spring Boot versions 3.0.0 - 3.0.5, 2.7.0 - 2.7.10, and older unsupported versions, an application that is deployed to Cloud Foundry could be susceptible to a security bypass. Users of affected versions should apply the following mitigation: 3.0.x users should upgrade to 3.0.6+. 2.7.x users should upgrade to 2.7.11+. Users of older, unsupported versions should upgrade to 3.0.6+ or 2.7.11+.
