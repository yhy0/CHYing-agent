# PyArrow: Arbitrary code execution when loading a malicious data file

**GHSA**: GHSA-5wvp-7f3h-6wmm | **CVE**: CVE-2023-47248 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **pyarrow** (pip): >= 0.14.0, < 14.0.1

## Description

Deserialization of untrusted data in IPC and Parquet readers in PyArrow versions 0.14.0 to 14.0.0 allows arbitrary code execution. An application is vulnerable if it reads Arrow IPC, Feather or Parquet data from untrusted sources (for example user-supplied input files).

This vulnerability only affects PyArrow, not other Apache Arrow implementations or bindings.

It is recommended that users of PyArrow upgrade to 14.0.1. Similarly, it is recommended that downstream libraries upgrade their dependency requirements to PyArrow 14.0.1 or later. PyPI packages are already available, and we hope that conda-forge packages will be available soon.

If it is not possible to upgrade, maintainers provide a separate package `pyarrow-hotfix` that disables the vulnerability on older PyArrow versions. See https://pypi.org/project/pyarrow-hotfix/  for instructions.
