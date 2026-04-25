# PyTorch Lightning path traversal vulnerability

**GHSA**: GHSA-4cv3-v7pv-rfhf | **CVE**: CVE-2024-8019 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-434

**Affected Packages**:
- **pytorch-lightning** (pip): < 2.4.0

## Description

In lightning-ai/pytorch-lightning version 2.3.2, a vulnerability exists in the `LightningApp` when running on a Windows host. The vulnerability occurs at the `/api/v1/upload_file/` endpoint, allowing an attacker to write or overwrite arbitrary files by providing a crafted filename. This can lead to potential remote code execution (RCE) by overwriting critical files or placing malicious files in sensitive locations.
