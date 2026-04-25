# vLLM affected by RCE via auto_map dynamic module loading during model initialization

**GHSA**: GHSA-2pc9-4j83-qjmr | **CVE**: CVE-2026-22807 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **vllm** (pip): >= 0.10.1, < 0.14.0

## Description

# Summary

vLLM loads Hugging Face `auto_map` dynamic modules during model resolution **without gating on `trust_remote_code`**, allowing attacker-controlled Python code in a model repo/path to execute at server startup.

---

# Impact

An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve **arbitrary code execution** on the vLLM host during model load.  
This happens **before any request handling** and does **not require API access**.

---

# Affected Versions

All versions where `vllm/model_executor/models/registry.py` resolves `auto_map` entries with `try_get_class_from_dynamic_module` **without checking `trust_remote_code`** (at least current `main`).

---

# Details

During model resolution, vLLM unconditionally iterates `auto_map` entries from the model config and calls `try_get_class_from_dynamic_module`, which delegates to Transformers’ `get_class_from_dynamic_module` and **executes the module code**.

This occurs even when `trust_remote_code` is `false`, allowing a malicious model repo to embed code in a referenced module and have it executed during initialization.

### Relevant code

- `vllm/model_executor/models/registry.py:856` — auto_map resolution  
- `vllm/transformers_utils/dynamic_module.py:13` — delegates to `get_class_from_dynamic_module`, which executes code

---

# Fixes

* https://github.com/vllm-project/vllm/pull/32194

# Credits

Reported by **bugbunny.ai**
