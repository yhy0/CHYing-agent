# Remote Code Execution due to Full Controled File Write in mlflow

**GHSA**: GHSA-5p3h-7fwh-92rc | **CVE**: CVE-2023-6018 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-78

**Affected Packages**:
- **mlflow** (pip): <= 2.8.1

## Description

The mlflow web server includes tools for tracking experiments, packaging code into reproducible runs, and sharing and deploying models. As this vulnerability allows to write / overwrite any file on the file system, it gives a lot of ways to archive code execution (like overwriting `/home/<user>/.bashrc`). A malicious user could use this issue to get command execution on the vulnerable machine and get access to data & models information.
