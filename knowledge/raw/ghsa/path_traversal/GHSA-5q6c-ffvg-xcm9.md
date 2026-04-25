# Remote code execution in mlflow

**GHSA**: GHSA-5q6c-ffvg-xcm9 | **CVE**: CVE-2024-0520 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22, CWE-23

**Affected Packages**:
- **mlflow** (pip): < 2.9.0

## Description

A vulnerability in mlflow/mlflow version 8.2.1 allows for remote code execution due to improper neutralization of special elements used in an OS command ('Command Injection') within the `mlflow.data.http_dataset_source.py` module. Specifically, when loading a dataset from a source URL with an HTTP scheme, the filename extracted from the `Content-Disposition` header or the URL path is used to generate the final file path without proper sanitization. This flaw enables an attacker to control the file path fully by utilizing path traversal or absolute path techniques, such as '../../tmp/poc.txt' or '/tmp/poc.txt', leading to arbitrary file write. Exploiting this vulnerability could allow a malicious user to execute commands on the vulnerable machine, potentially gaining access to data and model information. The issue is fixed in version 2.9.0.
