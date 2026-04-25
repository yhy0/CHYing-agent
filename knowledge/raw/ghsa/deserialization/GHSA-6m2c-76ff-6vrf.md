# Qiskit allows arbitrary code execution decoding QPY format versions < 13

**GHSA**: GHSA-6m2c-76ff-6vrf | **CVE**: CVE-2025-2000 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **qiskit-terra** (pip): >= 0.18.0, <= 0.46.3
- **qiskit** (pip): <= 1.4.1
- **qiskit** (pip): = 2.0.0rc1

## Description

### Impact

A maliciously crafted QPY file can potentially execute arbitrary-code embedded in the payload without privilege escalation when deserializing QPY formats < 13. A python process calling Qiskit's `qiskit.qpy.load()` function could potentially execute any arbitrary Python code embedded in the correct place in the binary file as part of a specially constructed payload.

### Patches

Fixed in Qiskit 1.4.2 and in Qiskit 2.0.0rc2
