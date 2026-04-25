# Go JOSE Signature Validation Bypass

**GHSA**: GHSA-77gc-fj98-665h | **CVE**: CVE-2016-9122 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-284

**Affected Packages**:
- **gopkg.in/square/go-jose.v1** (go): < 1.1.0

## Description

Go JOSE before 1.1.0 suffers from multiple signatures exploitation. The go-jose library supports messages with multiple signatures. However, when validating a signed message the API did not indicate which signature was valid, which could potentially lead to confusion. For example, users of the library might mistakenly read protected header values from an attached signature that was different from the one originally validated
