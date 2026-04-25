# JSONPath Plus Remote Code Execution (RCE) Vulnerability

**GHSA**: GHSA-pppg-cpfq-h7wr | **CVE**: CVE-2024-21534 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.webjars.npm:jsonpath-plus** (maven): <= 6.0.1
- **jsonpath-plus** (npm): < 10.2.0

## Description

Versions of the package jsonpath-plus before 10.0.7 are vulnerable to Remote Code Execution (RCE) due to improper input sanitization. An attacker can execute aribitrary code on the system by exploiting the unsafe default usage of vm in Node.

**Note:**

There were several attempts to fix it in versions [10.0.0-10.1.0](https://github.com/JSONPath-Plus/JSONPath/compare/v9.0.0...v10.1.0) but it could still be exploited using [different payloads](https://github.com/JSONPath-Plus/JSONPath/issues/226)
