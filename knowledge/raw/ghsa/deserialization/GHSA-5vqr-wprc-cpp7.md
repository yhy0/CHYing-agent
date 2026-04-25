# vLLM Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-5vqr-wprc-cpp7 | **CVE**: CVE-2024-11041 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **vllm** (pip): <= 0.6.2

## Description

vllm-project vllm version v0.6.2 contains a vulnerability in the MessageQueue.dequeue() API function. The function uses pickle.loads to parse received sockets directly, leading to a remote code execution vulnerability. An attacker can exploit this by sending a malicious payload to the MessageQueue, causing the victim's machine to execute arbitrary code.
