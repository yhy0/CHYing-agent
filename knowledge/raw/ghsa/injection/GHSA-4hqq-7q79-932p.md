# mcp-kubernetes-server has an OS Command Injection vulnerability

**GHSA**: GHSA-4hqq-7q79-932p | **CVE**: CVE-2025-59377 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-78

**Affected Packages**:
- **mcp-kubernetes-server** (pip): <= 0.1.11

## Description

`feiskyer/mcp-kubernetes-server` through **0.1.11** allows **OS command injection** via the `/mcp/kubectl` endpoint. The handler constructs a shell command with user-supplied arguments and executes it with `subprocess` using `shell=True`, enabling injection through shell metacharacters (e.g., `;`, `&&`, `$()`), even when the server is running in **read-only** mode.

A remote, unauthenticated attacker can execute arbitrary OS commands on the host, resulting in full compromise of confidentiality, integrity, and availability.

This issue is **distinct from** `mcp-server-kubernetes` and from **CVE-2025-53355**.
