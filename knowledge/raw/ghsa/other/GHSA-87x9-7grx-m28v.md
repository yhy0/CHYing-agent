# notation-go has excessive memory allocation on verification

**GHSA**: GHSA-87x9-7grx-m28v | **CVE**: CVE-2023-25656 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/notaryproject/notation-go** (go): < 1.0.0-rc.3

## Description

### Impact

`notation-go` users will find their application using excessive memory when verifying signatures and the application will be finally killed, and thus availability is impacted.

### Patches

The problem has been patched in the release [v1.0.0-rc.3](https://github.com/notaryproject/notation-go/releases/tag/v1.0.0-rc.3). Users should upgrade their `notation-go` packages to `v1.0.0-rc.3` or above.

### Workarounds

Users can review their own trust policy file and check if the identity string contains `=#`. Meanwhile, users should only put trusted certificates in their trust stores referenced by their own trust policy files, and make sure the `authenticity` validation is set to `enforce`

### Credits

The `notation-go` project would like to thank Adam Korczynski (@AdamKorcz) for responsibly disclosing this issue during a security fuzzing audit sponsored by CNCF and Shiwei Zhang (@shizhMSFT) for root cause analysis and detailed vulnerability report.

### References

- [Resource exhaustion attacks](https://en.wikipedia.org/wiki/Resource_exhaustion_attack)

