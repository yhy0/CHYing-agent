# vLLM introduced enhanced protection for CVE-2025-62164

**GHSA**: GHSA-mcmc-2m55-j8jj | **CVE**: N/A | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20, CWE-123, CWE-502, CWE-787

**Affected Packages**:
- **vllm** (pip): >= 0.10.2, < 0.11.1

## Description

### Summary
The fix [here](https://github.com/vllm-project/vllm/pull/27204) for CVE-2025-62164 is not sufficient. The fix only disables prompt embeds by default rather than addressing the root cause, so the DoS vulnerability remains when the feature is enabled.

### Details
vLLM's pending change attempts to fix the root cause, which is the missing sparse tensor validation.  PyTorch (~v2.0) disables sparse tensor validation (specifically, sparse tensor invariants checks) by default for performance reasons.  vLLM is adding the sparse tensor validation to ensure indices are valid, non-negative, and within bounds.  These checks help catch malformed tensors.

### PoC
NA

### Impact
Current fix only added a flag to disable/enable prompt embeds, so by default, prompt embeds feature is disabled in vLLM, which stops DoS attacks through the embeddings.  However, It doesn’t address the problem when the flag is enabled and there is still potential for DoS attacks.

### Changes

* https://github.com/vllm-project/vllm/pull/30649
