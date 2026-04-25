# Duplicate Advisory: Permissive Regular Expression in tacquito

**GHSA**: GHSA-j42f-wc6v-5xpq | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: N/A

**Affected Packages**:
- **github.com/tacquito/tacquito** (go): < 0.0.0-20241011192817-07b49d1358e6

## Description

Tacquito prior to commit 07b49d1358e6ec0b5aa482fcd284f509191119e2 was not properly performing regex matches on authorized commands and arguments. Configured allowed commands/arguments were intended to require a match on the entire string, but instead only enforced a match on a sub-string. That would have potentially allowed unauthorized commands to be executed.
