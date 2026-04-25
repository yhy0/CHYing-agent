# InvokeAI Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-mcrp-whpw-jp68 | **CVE**: CVE-2024-12029 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **InvokeAI** (pip): >= 5.3.1, < 5.4.3rc2

## Description

A remote code execution vulnerability exists in invoke-ai/invokeai versions 5.3.1 through 5.4.2 via the /api/v2/models/install API. The vulnerability arises from unsafe deserialization of model files using torch.load without proper validation. Attackers can exploit this by embedding malicious code in model files, which is executed upon loading. This issue is fixed in version 5.4.3rc2.
