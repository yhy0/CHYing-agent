# TorchServe Pre-Auth Remote Code Execution

**GHSA**: GHSA-4mqg-h5jf-j9m7 | **CVE**: N/A | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-913

**Affected Packages**:
- **torchserve** (pip): >= 0.3.0, < 0.8.2

## Description

## Impact

**Use of Open Source Library potentially exposed to RCE**
    **Issue**: Use of a version of the SnakeYAML `v1.31 `open source library with multiple issues that potentially exposes the user to unsafe deserialization of Java objects. This could allow third parties to execute arbitrary code on the target system. This issue is present in versions `0.3.0` to `0.8.1`.
    **Mitigation**: A pull request to address this issue has been merged - https://github.com/pytorch/serve/pull/2523. TorchServe release `0.8.2` includes this fix.

## Patches

## TorchServe release 0.8.2 includes fixes to address the previously listed issue:

https://github.com/pytorch/serve/releases/tag/v0.8.2

**Tags for upgraded DLC release**
User can use the following new image tags to pull DLCs that ship with patched TorchServe version 0.8.2:
x86 GPU

* v1.9-pt-ec2-2.0.1-inf-gpu-py310
* v1.8-pt-sagemaker-2.0.1-inf-gpu-py310

x86 CPU

* v1.8-pt-ec2-2.0.1-inf-cpu-py310
* v1.7-pt-sagemaker-2.0.1-inf-cpu-py310

Graviton

* v1.7-pt-graviton-ec2-2.0.1-inf-cpu-py310
* v1.5-pt-graviton-sagemaker-2.0.1-inf-cpu-py310

Neuron

* 1.13.1-neuron-py310-sdk2.13.2-ubuntu20.04
* 1.13.1-neuronx-py310-sdk2.13.2-ubuntu20.04
* 1.13.1-neuronx-py310-sdk2.13.2-ubuntu20.04

The full DLC image URI details can be found at: https://github.com/aws/deep-learning-containers/blob/master/available_images.md#available-deep-learning-containers-images

## References
https://github.com/pytorch/serve/pull/2523
https://github.com/pytorch/serve/releases/tag/v0.8.2
https://github.com/aws/deep-learning-containers/blob/master/available_images.md#available-deep-learning-containers-images

## Credit
We would like to thank Oligo Security for responsibly disclosing this issue and working with us on its resolution.
If you have any questions or comments about this advisory, we ask that you contact AWS/Amazon Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting[)](https://aws.amazon.com/security/vulnerability-reporting)) or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.
