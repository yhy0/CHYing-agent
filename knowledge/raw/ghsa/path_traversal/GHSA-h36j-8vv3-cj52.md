# Open Neural Network Exchange (ONNX) Path Traversal Vulnerability

**GHSA**: GHSA-h36j-8vv3-cj52 | **CVE**: CVE-2024-7776 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **onnx** (pip): < 1.17.0

## Description

A vulnerability in the `download_model` function of the onnx/onnx framework, before and including version 1.16.1, allows for arbitrary file overwrite due to inadequate prevention of path traversal attacks in malicious tar files. This vulnerability can be exploited by an attacker to overwrite files in the user's directory, potentially leading to remote command execution.
