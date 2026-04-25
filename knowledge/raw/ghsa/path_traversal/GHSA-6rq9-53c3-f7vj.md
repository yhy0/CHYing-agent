# onnx allows Arbitrary File Overwrite in download_model_with_test_data

**GHSA**: GHSA-6rq9-53c3-f7vj | **CVE**: CVE-2024-5187 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **onnx** (pip): < 1.16.2

## Description

A vulnerability in the `download_model_with_test_data` function of the onnx/onnx framework, versions before 1.16.2, allow for arbitrary file overwrite due to inadequate prevention of path traversal attacks in malicious tar files. This vulnerability enables attackers to overwrite any file on the system, potentially leading to remote code execution, deletion of system, personal, or application files, thus impacting the integrity and availability of the system. The issue arises from the function's handling of tar file extraction without performing security checks on the paths within the tar file, as demonstrated by the ability to overwrite the `/home/kali/.ssh/authorized_keys` file by specifying an absolute path in the malicious tar file.
