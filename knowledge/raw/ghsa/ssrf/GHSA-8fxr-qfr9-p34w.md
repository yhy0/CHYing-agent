# TorchServe Server-Side Request Forgery vulnerability

**GHSA**: GHSA-8fxr-qfr9-p34w | **CVE**: CVE-2023-43654 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-918

**Affected Packages**:
- **torchserve** (pip): >= 0.1.0, < 0.8.2

## Description

## Impact
**Remote Server-Side Request Forgery (SSRF)**
    **Issue**: TorchServe default configuration lacks proper input validation, enabling third parties to invoke remote HTTP download requests and write files to the disk. This issue could be taken advantage of to compromise the integrity of the system and sensitive data. This issue is present in versions `0.1.0` to `0.8.1`.
    **Mitigation**: The user is able to load the model of their choice from any URL that they would like to use. The user of TorchServe is responsible for configuring both the [allowed_urls](https://github.com/pytorch/serve/blob/b3eced56b4d9d5d3b8597aa506a0bcf954d291bc/docs/configuration.md?plain=1#L296) and specifying the model URL to be used. A pull request to warn the user when the default value for `allowed_urls` is used has been merged - https://github.com/pytorch/serve/pull/2534. TorchServe release `0.8.2` includes this change.

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
https://github.com/pytorch/serve/blob/b3eced56b4d9d5d3b8597aa506a0bcf954d291bc/docs/configuration.md?plain=1#L296
https://github.com/pytorch/serve/pull/2534
https://github.com/pytorch/serve/releases/tag/v0.8.2
https://github.com/aws/deep-learning-containers/blob/master/available_images.md#available-deep-learning-containers-images

## Credit
We would like to thank Oligo Security for responsibly disclosing this issue and working with us on its resolution.
If you have any questions or comments about this advisory, we ask that you contact AWS/Amazon Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting[)](https://aws.amazon.com/security/vulnerability-reporting)) or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.
