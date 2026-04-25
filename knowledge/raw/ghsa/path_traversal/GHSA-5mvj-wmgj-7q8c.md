# mlflow vulnerable to Path Traversal

**GHSA**: GHSA-5mvj-wmgj-7q8c | **CVE**: CVE-2024-1560 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **mlflow** (pip): <= 2.9.2

## Description

A path traversal vulnerability exists in the mlflow/mlflow repository, specifically within the artifact deletion functionality. Attackers can bypass path validation by exploiting the double decoding process in the `_delete_artifact_mlflow_artifacts` handler and `local_file_uri_to_path` function, allowing for the deletion of arbitrary directories on the server's filesystem. This vulnerability is due to an extra unquote operation in the `delete_artifacts` function of `local_artifact_repo.py`, which fails to properly sanitize user-supplied paths. The issue is present up to version 2.9.2, despite attempts to fix a similar issue in CVE-2023-6831.
