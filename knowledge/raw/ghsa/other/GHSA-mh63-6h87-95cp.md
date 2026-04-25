# jwt-go allows excessive memory allocation during header parsing

**GHSA**: GHSA-mh63-6h87-95cp | **CVE**: CVE-2025-30204 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-405

**Affected Packages**:
- **github.com/golang-jwt/jwt/v5** (go): >= 5.0.0-rc.1, < 5.2.2
- **github.com/golang-jwt/jwt/v4** (go): < 4.5.2
- **github.com/golang-jwt/jwt** (go): >= 3.2.0, <= 3.2.2

## Description

### Summary

Function [`parse.ParseUnverified`](https://github.com/golang-jwt/jwt/blob/c035977d9e11c351f4c05dfeae193923cbab49ee/parser.go#L138-L139) currently splits (via a call to [strings.Split](https://pkg.go.dev/strings#Split)) its argument (which is untrusted data) on periods.

As a result, in the face of a malicious request whose _Authorization_ header consists of `Bearer ` followed by many period characters, a call to that function incurs allocations to the tune of O(n) bytes (where n stands for the length of the function's argument), with a constant factor of about 16. Relevant weakness: [CWE-405: Asymmetric Resource Consumption (Amplification)](https://cwe.mitre.org/data/definitions/405.html)

### Details

See [`parse.ParseUnverified`](https://github.com/golang-jwt/jwt/blob/c035977d9e11c351f4c05dfeae193923cbab49ee/parser.go#L138-L139) 

### Impact

Excessive memory allocation
