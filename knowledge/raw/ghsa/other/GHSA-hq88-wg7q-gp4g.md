# mlflow vulnerable to Path Traversal

**GHSA**: GHSA-hq88-wg7q-gp4g | **CVE**: CVE-2024-3573 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-29

**Affected Packages**:
- **mlflow** (pip): < 2.10.0

## Description

mlflow/mlflow is vulnerable to Local File Inclusion (LFI) due to improper parsing of URIs, allowing attackers to bypass checks and read arbitrary files on the system. The issue arises from the 'is_local_uri' function's failure to properly handle URIs with empty or 'file' schemes, leading to the misclassification of URIs as non-local. Attackers can exploit this by crafting malicious model versions with specially crafted 'source' parameters, enabling the reading of sensitive files within at least two directory levels from the server's root.
