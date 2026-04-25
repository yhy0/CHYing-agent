# Duplicate Advisory: Qiskit allows arbitrary code execution decoding QPY format versions < 13

**GHSA**: GHSA-3pwp-2fqj-6g2p | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **qiskit** (pip): <= 1.4.1

## Description

# Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-6m2c-76ff-6vrf. This link is maintained to preserve external references.

# Original Description
A maliciously crafted QPY file can potential execute arbitrary-code embedded in the payload without privilege escalation when deserialising QPY formats < 13. A python process calling Qiskit 0.18.0 through 1.4.1's `qiskit.qpy.load()` function could potentially execute any arbitrary Python code embedded in the correct place in the binary file as part of specially constructed payload.
