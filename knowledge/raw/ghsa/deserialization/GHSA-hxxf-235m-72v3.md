# Deserialization of Untrusted Data in Hugging Face Transformers

**GHSA**: GHSA-hxxf-235m-72v3 | **CVE**: CVE-2024-11394 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **transformers** (pip): >= 0, < 4.48.0

## Description

Hugging Face Transformers Trax Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of model files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25012.
