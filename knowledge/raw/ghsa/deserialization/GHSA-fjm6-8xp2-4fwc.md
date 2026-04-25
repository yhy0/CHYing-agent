# Boltz contains an insecure deserialization vulnerability in its molecule loading functionality

**GHSA**: GHSA-fjm6-8xp2-4fwc | **CVE**: CVE-2025-70560 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-502

**Affected Packages**:
- **boltz** (pip): <= 2.0.0

## Description

Boltz 2.0.0 contains an insecure deserialization vulnerability in its molecule loading functionality. The application uses Python pickle to deserialize molecule data files without validation. An attacker with the ability to place a malicious pickle file in a directory processed by boltz can achieve arbitrary code execution when the file is loaded.
