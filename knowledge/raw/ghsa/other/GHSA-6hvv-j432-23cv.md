# Weave GitOps Terraform Controller Information Disclosure Vulnerability

**GHSA**: GHSA-6hvv-j432-23cv | **CVE**: CVE-2023-34236 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-200, CWE-312, CWE-522, CWE-532

**Affected Packages**:
- **github.com/weaveworks/tf-controller** (go): < 0.14.4
- **github.com/weaveworks/tf-controller** (go): >= 0.15.0-rc.1, < 0.15.0-rc.5

## Description

### Impact

A vulnerability has been identified in Weave GitOps Terraform Controller which could allow an authenticated remote attacker to view sensitive information. This vulnerability stems from Weave GitOps Terraform Runners (`tf-runner`), where sensitive data is inadvertently printed - potentially revealing sensitive user data in their pod logs. In particular, functions `tfexec.ShowPlan`, `tfexec.ShowPlanRaw`, and `tfexec.Output` are implicated when the `tfexec` object set its `Stdout` and `Stderr` to be `os.Stdout` and `os.Stderr`.

An unauthorized remote attacker could exploit this vulnerability by accessing these prints of sensitive information, which may contain configurations or tokens that could be used to gain unauthorized control or access to resources managed by the Terraform controller.

A successful exploit could allow the attacker to utilize this sensitive data, potentially leading to unauthorized access or control of the system.

### Patches

This vulnerability has been addressed in Weave GitOps Terraform Controller versions `v0.14.4` and `v0.15.0-rc.5`. Users are urged to upgrade to one of these versions to mitigate the vulnerability.

The patches for this vulnerability are found in:
- this commit: 9708fda28ccd0466cb0a8fd409854ab4d92f7dca
- this commit: 6323b355bd7f5d2ce85d0244fe0883af3881df4e
- this commit: 28282bc644054e157c3b9a3d38f1f9551ce09074
- and this commit: 98a0688036e9dbcf43fa84960d9a1ef3e09a69cf

### Workarounds

As a temporary measure until the patch can be applied, users can add the environment variable `DISABLE_TF_LOGS` to the tf-runners via the runner pod template of the Terraform Custom Resource. This will prevent the logging of sensitive information and mitigate the risk of this vulnerability.

### References

- The first issue: https://github.com/weaveworks/tf-controller/issues/637
- The second issue: https://github.com/weaveworks/tf-controller/issues/649

### For More Information

If you have any further questions or comments about this advisory:

Open an issue in the Weave GitOps Terraform Controller repository
Email us at [security@weave.works](mailto:security@weave.works)

