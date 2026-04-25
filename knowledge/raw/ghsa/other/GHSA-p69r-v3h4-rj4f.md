# Duplicate Advisory: github.com/gogs/gogs affected by CVE-2024-39930

**GHSA**: GHSA-p69r-v3h4-rj4f | **CVE**: N/A | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-88

**Affected Packages**:
- **github.com/gogs/gogs** (go): <= 0.13.0

## Description

# Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-vm62-9jw3-c8w3. This link is maintained to preserve external references.

# Original Description
The built-in SSH server of Gogs through 0.13.0 allows argument injection in internal/ssh/ssh.go, leading to remote code execution. Authenticated attackers can exploit this by opening an SSH connection and sending a malicious --split-string env request if the built-in SSH server is activated. Windows installations are unaffected.
