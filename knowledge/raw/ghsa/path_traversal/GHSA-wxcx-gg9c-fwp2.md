# TorchServe vulnerable to bypass of allowed_urls configuration

**GHSA**: GHSA-wxcx-gg9c-fwp2 | **CVE**: CVE-2024-35198 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-706

**Affected Packages**:
- **torchserve** (pip): < 0.11.0

## Description

### Impact
TorchServe's check on allowed_urls configuration can be by-passed if the URL contains characters such as ".." but it does not prevent the model from being downloaded into the model store. Once a file is downloaded, it can be referenced without providing a URL the second time, which effectively bypasses the allowed_urls security check. Customers using PyTorch inference Deep Learning Containers (DLC) through Amazon SageMaker and EKS are not affected.

### Patches
This issue in TorchServe has been fixed by validating the URL without characters such as ".." before downloading: [#3082](https://github.com/pytorch/serve/pull/3082).

TorchServe release 0.11.0 includes the fix to address this vulnerability.

### References
* [#3082](https://github.com/pytorch/serve/pull/3082)
* [TorchServe release v0.11.0](https://github.com/pytorch/serve/releases/tag/v0.11.0)

Thank Kroll Cyber Risk for for responsibly disclosing this issue.

If you have any questions or comments about this advisory, we ask that you contact AWS Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting) or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.
