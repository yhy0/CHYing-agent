# llama-index-core Prompt Injection vulnerability leading to Arbitrary Code Execution

**GHSA**: GHSA-wvpx-g427-q9wc | **CVE**: CVE-2024-3098 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **llama-index-core** (pip): < 0.10.24

## Description

A vulnerability was identified in the `exec_utils` class of the `llama_index` package, specifically within the `safe_eval` function, allowing for prompt injection leading to arbitrary code execution. This issue arises due to insufficient validation of input, which can be exploited to bypass method restrictions and execute unauthorized code. The vulnerability is a bypass of the previously addressed CVE-2023-39662, demonstrated through a proof of concept that creates a file on the system by exploiting the flaw.
