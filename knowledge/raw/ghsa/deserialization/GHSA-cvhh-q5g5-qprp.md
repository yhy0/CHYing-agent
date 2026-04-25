# Keras framework vulnerable to deserialization of untrusted data

**GHSA**: GHSA-cvhh-q5g5-qprp | **CVE**: CVE-2025-49655 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **keras** (pip): >= 3.11.0, < 3.11.3

## Description

Deserialization of untrusted data can occur in versions of the Keras framework running versions 3.11.0 up to but not including 3.11.3, enabling a maliciously uploaded Keras file containing a TorchModuleWrapper class to run arbitrary code on an end user’s system when loaded despite safe mode being enabled. The vulnerability can be triggered through both local and remote files.
