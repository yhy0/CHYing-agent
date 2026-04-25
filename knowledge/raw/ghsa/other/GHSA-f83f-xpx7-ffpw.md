# Fulcio allocates excessive memory during token parsing

**GHSA**: GHSA-f83f-xpx7-ffpw | **CVE**: CVE-2025-66506 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-405

**Affected Packages**:
- **github.com/sigstore/fulcio** (go): <= 1.8.2

## Description

Function [identity.extractIssuerURL](https://github.com/sigstore/fulcio/blob/main/pkg/identity/issuerpool.go#L44-L45) currently splits (via a call to [strings.Split](https://pkg.go.dev/strings#Split)) its argument (which is untrusted data) on periods.

As a result, in the face of a malicious request with an (invalid) OIDC identity token in the payload containing many period characters, a call to `extractIssuerURL` incurs allocations to the tune of O(n) bytes (where n stands for the length of the function's argument), with a constant factor of about 16. Relevant weakness: [CWE-405: Asymmetric Resource Consumption (Amplification)](https://cwe.mitre.org/data/definitions/405.html)

Details
See [identity.extractIssuerURL](https://github.com/sigstore/fulcio/blob/main/pkg/identity/issuerpool.go#L44-L45)

Impact
Excessive memory allocation
