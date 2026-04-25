# GitPython vulnerable to remote code execution due to insufficient sanitization of input arguments

**GHSA**: GHSA-pr76-5cm5-w9cj | **CVE**: CVE-2023-40267 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-78

**Affected Packages**:
- **GitPython** (pip): < 3.1.32

## Description

GitPython before 3.1.32 does not block insecure non-multi options in `clone` and `clone_from`, making it vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. Exploiting this vulnerability is possible because the library makes external calls to git without sufficient sanitization of input arguments. NOTE: this issue exists because of an incomplete fix for CVE-2022-24439.
