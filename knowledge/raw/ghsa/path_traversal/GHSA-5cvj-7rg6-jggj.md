# MLflow Tracking Server Model Creation Directory Traversal Remote Code Execution Vulnerability

**GHSA**: GHSA-5cvj-7rg6-jggj | **CVE**: CVE-2025-11201 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **mlflow** (pip): >= 3.0.0rc0, < 3.0.0
- **mlflow** (pip): < 2.22.4

## Description

MLflow Tracking Server Model Creation Directory Traversal Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of MLflow Tracking Server. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the handling of model file paths. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-26921.
