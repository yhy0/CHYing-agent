# Kedro allows Remote Code Execution by Pulling Micro Packages

**GHSA**: GHSA-rm69-wvpv-r2w7 | **CVE**: CVE-2024-12215 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20, CWE-94, CWE-829

**Affected Packages**:
- **kedro** (pip): <= 0.19.8

## Description

In kedro-org/kedro version 0.19.8, the `pull_package()` API function allows users to download and extract micro packages from the Internet. However, the function `project_wheel_metadata()` within the code path can execute the `setup.py` file inside the tar file, leading to remote code execution (RCE) by running arbitrary commands on the victim's machine.
