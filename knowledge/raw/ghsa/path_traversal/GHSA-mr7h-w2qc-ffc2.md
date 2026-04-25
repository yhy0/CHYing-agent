# pytorch-lightning vulnerable to Arbitrary File Write via /v1/runs API endpoint

**GHSA**: GHSA-mr7h-w2qc-ffc2 | **CVE**: CVE-2024-5980 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22, CWE-434

**Affected Packages**:
- **lightning** (pip): <= 2.3.1

## Description

A vulnerability in the /v1/runs API endpoint of lightning-ai/pytorch-lightning v2.2.4 allows attackers to exploit path traversal when extracting tar.gz files. When the LightningApp is running with the plugin_server, attackers can deploy malicious tar.gz plugins that embed arbitrary files with path traversal vulnerabilities. This can result in arbitrary files being written to any directory in the victim's local file system, potentially leading to remote code execution.
