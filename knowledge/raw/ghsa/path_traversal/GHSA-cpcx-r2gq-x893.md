# LocalAI path traversal vulnerability

**GHSA**: GHSA-cpcx-r2gq-x893 | **CVE**: CVE-2024-5182 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/go-skynet/LocalAI** (go): < 2.16.0

## Description

A path traversal vulnerability exists in mudler/localai version 2.14.0, where an attacker can exploit the `model` parameter during the model deletion process to delete arbitrary files. Specifically, by crafting a request with a manipulated `model` parameter, an attacker can traverse the directory structure and target files outside of the intended directory, leading to the deletion of sensitive data. This vulnerability is due to insufficient input validation and sanitization of the `model` parameter.
