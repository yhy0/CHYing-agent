# PyTorch Vulnerable to Remote Code Execution via Untrusted Checkpoint Files

**GHSA**: GHSA-63cw-57p8-fm3p | **CVE**: CVE-2026-24747 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-502

**Affected Packages**:
- **pytorch** (pip): < 2.10.0

## Description

### Summary

A vulnerability in PyTorch's `weights_only` unpickler allows an attacker to craft a malicious checkpoint file (`.pth`) that, when loaded with `torch.load(..., weights_only=True)`, can corrupt memory and potentially lead to arbitrary code execution.

### Vulnerability Details

The `weights_only=True` unpickler failed to properly validate pickle opcodes and storage metadata, allowing:

1. **Heap memory corruption** via `SETITEM`/`SETITEMS` opcodes applied to non-dictionary types
2. **Storage size mismatch** between declared element count and actual data in the archive

### Impact

An attacker who can convince a user to load a malicious checkpoint file may achieve arbitrary code execution in the context of the victim's process.


# Credit
Ji'an Zhou
