# AgentScope path traversal vulnerability in save-workflow

**GHSA**: GHSA-j9rw-qm5f-r8xm | **CVE**: CVE-2024-8551 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22, CWE-23

**Affected Packages**:
- **agentscope** (pip): <= 0.1.1

## Description

A path traversal vulnerability exists in the save-workflow and load-workflow functionality of modelscope/agentscope versions prior to the fix. This vulnerability allows an attacker to read and write arbitrary JSON files on the filesystem, potentially leading to the exposure or modification of sensitive information such as configuration files, API keys, and hardcoded passwords.
