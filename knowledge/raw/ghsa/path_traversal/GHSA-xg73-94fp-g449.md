# mlflow is vulnerable to remote file access in `mlflow server` and `mlflow ui` CLIs

**GHSA**: GHSA-xg73-94fp-g449 | **CVE**: CVE-2023-1177 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-29

**Affected Packages**:
- **mlflow** (pip): <= 2.2.0

## Description

### Impact

Users of the MLflow Open Source Project who are hosting the MLflow Model Registry using the `mlflow server` or `mlflow ui` commands using an MLflow version older than MLflow 2.2.1 may be vulnerable to a remote file access exploit if they are not limiting who can query their server (for example, by using a cloud VPC, an IP allowlist for inbound requests, or authentication / authorization middleware).

This issue only affects users and integrations that run the `mlflow server` and `mlflow ui` commands. Integrations that do not make use of `mlflow server` or `mlflow ui` are unaffected; for example, the Databricks Managed MLflow product and MLflow on Azure Machine Learning do not make use of these commands and are not impacted by these vulnerabilities in any way.

The vulnerability detailed in https://nvd.nist.gov/vuln/detail/CVE-2023-1177 enables an actor to download arbitrary files unrelated to MLflow from the host server, including any files stored in remote locations to which the host server has access.

### Patches
This vulnerability has been patched in MLflow 2.2.1, which was released to PyPI on March 2nd, 2023. If you are using `mlflow server` or `mlflow ui` with the MLflow Model Registry, we recommend upgrading to MLflow 2.2.1 as soon as possible.

### Workarounds
If you are using the MLflow open source `mlflow server` or `mlflow ui` commands, we strongly recommend limiting who can access your MLflow Model Registry and MLflow Tracking servers using a cloud VPC, an IP allowlist for inbound requests, authentication / authorization middleware, or another access restriction mechanism of your choosing.

If you are using the MLflow open source `mlflow server` or `mlflow ui` commands, we also strongly recommend limiting the remote files to which your MLflow Model Registry and MLflow Tracking servers have access. For example, if your MLflow Model Registry or MLflow Tracking server uses cloud-hosted blob storage for MLflow artifacts, make sure to restrict the scope of your server's cloud credentials such that it can only access files and directories related to MLflow.

### References
More information about the vulnerability is available at https://nvd.nist.gov/vuln/detail/CVE-2023-1177.
