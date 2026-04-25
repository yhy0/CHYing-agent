# notation-go's verification bypass can cause users to verify the wrong artifact

**GHSA**: GHSA-xhg5-42rf-296r | **CVE**: CVE-2023-33959 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-347

**Affected Packages**:
- **github.com/notaryproject/notation-go** (go): < 1.0.0-rc.6

## Description

### Impact
An attacker who controls or compromises a registry can lead a user to verify the wrong artifact.

### Patches
The problem has been fixed in the release [v1.0.0-rc.6](https://github.com/notaryproject/notation-go/releases/tag/v1.0.0-rc.6). Users should upgrade their notation-go library to [v1.0.0-rc.6](https://github.com/notaryproject/notation-go/releases/tag/v1.0.0-rc.6) or above.

### Workarounds
User should use secure and trusted container registries.

### Credits
The `notation` project would like to thank Adam Korczynski (@AdamKorcz) for responsibly disclosing the issue found during an security audit (facilitated by OSTIF and sponsored by CNCF) and Shiwei Zhang (@shizhMSFT), Pritesh Bandi (@priteshbandi)  for root cause analysis.

