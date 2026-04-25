# Code execution in pandasai

**GHSA**: GHSA-5g73-69p4-7gvx | **CVE**: CVE-2024-23752 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94, CWE-862

**Affected Packages**:
- **pandasai** (pip): <= 1.5.17

## Description

GenerateSDFPipeline in synthetic_dataframe in PandasAI (aka pandas-ai) through 1.5.17 allows attackers to trigger the generation of arbitrary Python code that is executed by SDFCodeExecutor. An attacker can create a dataframe that provides an English language specification of this Python code. NOTE: the vendor previously attempted to restrict code execution in response to a separate issue, CVE-2023-39660.
