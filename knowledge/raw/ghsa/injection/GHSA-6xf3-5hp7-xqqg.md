# Improper token validation leading to code execution in Teleport

**GHSA**: GHSA-6xf3-5hp7-xqqg | **CVE**: CVE-2022-36633 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20, CWE-77

**Affected Packages**:
- **github.com/gravitational/teleport** (go): < 8.3.17
- **github.com/gravitational/teleport** (go): >= 9.0.0, < 9.3.13
- **github.com/gravitational/teleport** (go): >= 10.0.0, < 10.1.2

## Description

Teleport 9.3.6 is vulnerable to Command injection leading to Remote Code Execution. An attacker can craft a malicious ssh agent installation link by URL encoding a bash escape with carriage return line feed. This url encoded payload can be used in place of a token and sent to a user in a social engineering attack. This is fully unauthenticated attack utilizing the trusted teleport server to deliver the payload.
