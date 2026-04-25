# RunGptLLM class in LlamaIndex has a command injection

**GHSA**: GHSA-pw38-xv9x-h8ch | **CVE**: CVE-2024-4181 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **llama-index** (pip): < 0.10.13
- **llama-index-llms-rungpt** (pip): < 0.1.3

## Description

A command injection vulnerability exists in the RunGptLLM class of the llama_index library, version 0.9.47, used by the RunGpt framework from JinaAI to connect to Language Learning Models (LLMs). The vulnerability arises from the improper use of the eval function, allowing a malicious or compromised LLM hosting provider to execute arbitrary commands on the client's machine. This issue was fixed in version 0.10.13. The exploitation of this vulnerability could lead to a hosting provider gaining full control over client machines.
