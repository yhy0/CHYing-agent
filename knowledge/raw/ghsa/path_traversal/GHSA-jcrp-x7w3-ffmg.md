# Deep Java Library path traversal issue

**GHSA**: GHSA-jcrp-x7w3-ffmg | **CVE**: CVE-2025-0851 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-36

**Affected Packages**:
- **ai.djl:api** (maven): < 0.31.1

## Description

## Summary

[Deep Java Library (DJL)](https://docs.djl.ai/master/index.html) is an open-source, high-level, engine-agnostic Java framework for deep learning. DJL is designed to be easy to get started with and simple to use for Java developers. DJL provides a native Java development experience and functions like any other regular Java library.

DJL provides utilities for extracting tar and zip model archives that are used when loading models for use with DJL. These utilities were found to contain issues that do not protect against absolute path traversal during the extraction process.

## Impact

An issue exists with DJL's untar and unzip functionalities. Specifically, it is possible to create an archive on a Windows system, and when extracted on a MacOS or Linux system, write artifacts outside the intended destination during the extraction process. The reverse is also true for archives created on MacOS/Linux systems and extracted on Windows systems.

Impacted versions: 0.1.0 - 0.31.0

## Patches

This issue has been patched in DJL 0.31.1 [1]

## Workarounds

Do not use model archive files from sources you do not trust. You should only use model archives from official sources like the DJL Model Zoo, or models that you have created and packaged yourself.

## References

If you have any questions or comments about this advisory, we ask that you contact AWS/Amazon Security via our vulnerability reporting page [2] or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.

[1] https://github.com/deepjavalibrary/djl/tree/v0.31.1
[2] https://aws.amazon.com/security/vulnerability-reporting
