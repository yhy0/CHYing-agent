# Path Traversal in Apache Shiro

**GHSA**: GHSA-pmhc-2g4f-85cg | **CVE**: CVE-2023-34478 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22

**Affected Packages**:
- **org.apache.shiro:shiro-web** (maven): < 1.12.0
- **org.apache.shiro:shiro-web** (maven): >= 2.0.0-alpha-1, < 2.0.0-alpha-3

## Description

Apache Shiro, before 1.12.0 or 2.0.0-alpha-3, may be susceptible to a path traversal attack that results in an authentication bypass when used together with APIs or other web frameworks that route requests based on non-normalized requests.

Mitigation: Update to Apache Shiro 1.12.0+ or 2.0.0-alpha-3+
