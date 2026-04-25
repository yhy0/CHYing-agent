# Duplicate Advisory: Keras keras.utils.get_file API is vulnerable to a path traversal attack

**GHSA**: GHSA-9g7v-8wxv-mwxp | **CVE**: CVE-2025-12638 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-22

**Affected Packages**:
- **Keras** (pip): < 3.12.0

## Description

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-hjqc-jx6g-rwp9. This link is maintained to preserve external references.

### Original Description
Keras version 3.11.3 is affected by a path traversal vulnerability in the keras.utils.get_file() function when extracting tar archives. The vulnerability arises because the function uses Python's tarfile.extractall() method without the security-critical filter='data' parameter. Although Keras attempts to filter unsafe paths using filter_safe_paths(), this filtering occurs before extraction, and a PATH_MAX symlink resolution bug triggers during extraction. This bug causes symlink resolution to fail due to path length limits, resulting in a security bypass that allows files to be written outside the intended extraction directory. This can lead to arbitrary file writes outside the cache directory, enabling potential system compromise or malicious code execution. The vulnerability affects Keras installations that process tar archives with get_file() and does not affect versions where this extraction method is secured with the appropriate filter parameter.
