# AgentScope Deserialization Vulnerability

**GHSA**: GHSA-9w5h-67gf-xvv8 | **CVE**: CVE-2024-8502 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **agentscope** (pip): <= 0.0.6a3

## Description

A vulnerability in the RpcAgentServerLauncher class of modelscope/agentscope v0.0.6a3 allows for remote code execution (RCE) via deserialization of untrusted data using the dill library. The issue occurs in the AgentServerServicer.create_agent method, where serialized input is deserialized using dill.loads, enabling an attacker to execute arbitrary commands on the server.
