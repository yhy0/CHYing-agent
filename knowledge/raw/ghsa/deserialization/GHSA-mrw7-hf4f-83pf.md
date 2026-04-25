# vLLM deserialization vulnerability leading to DoS and potential RCE

**GHSA**: GHSA-mrw7-hf4f-83pf | **CVE**: CVE-2025-62164 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20, CWE-123, CWE-502, CWE-787

**Affected Packages**:
- **vllm** (pip): >= 0.10.2, < 0.11.1

## Description

### Summary
A memory corruption vulnerability that leading to a crash (denial-of-service) and potentially remote code execution (RCE) exists in vLLM versions 0.10.2 and later, in the Completions API endpoint. When processing user-supplied prompt embeddings, the endpoint loads serialized tensors using torch.load() without sufficient validation.

Due to a change introduced in PyTorch 2.8.0, sparse tensor integrity checks are disabled by default. As a result, maliciously crafted tensors can bypass internal bounds checks and trigger an out-of-bounds memory write during the call to to_dense(). This memory corruption can crash vLLM and potentially lead to code execution on the server hosting vLLM.

### Details
A vulnerability that can lead to RCE from the completions API endpoint exists in vllm, where due to missing checks when loading user-provided tensors, an out-of-bounds write can be triggered. This happens because the default behavior of `torch.load(tensor, weights_only=True)`  since pytorch 2.8.0 is to not perform validity checks for sparse tensors, and this needs to be enabled explicitly using the [torch.sparse.check_sparse_tensor_invariants](https://docs.pytorch.org/docs/stable/generated/torch.sparse.check_sparse_tensor_invariants.html) context manager.

The vulnerability is in the following code in [vllm/entrypoints/renderer.py:148](https://github.com/vllm-project/vllm/blob/a332b84578cdc0706e040f6a765954c8a289904f/vllm/entrypoints/renderer.py#L148)

```python
    def _load_and_validate_embed(embed: bytes) -> EngineEmbedsPrompt:
        tensor = torch.load(
            io.BytesIO(pybase64.b64decode(embed, validate=True)),
            weights_only=True,
            map_location=torch.device("cpu"),
        )
        assert isinstance(tensor, torch.Tensor) and tensor.dtype in (
            torch.float32,
            torch.bfloat16,
            torch.float16,
        )
        tensor = tensor.to_dense()
```

Because of the missing checks, loading invalid prompt embedding tensors provided by the user can cause an out-of-bounds write in the call to `to_dense` .

### Impact
All users with access to this API are able to exploit this vulnerability. Unsafe deserialization of untrusted input can be abused to achieve DoS and potentially remote code execution (RCE) in the vLLM server process. This impacts deployments running vLLM as a server or any instance that deserializes untrusted/model-provided payloads.

## Fix

https://github.com/vllm-project/vllm/pull/27204

## Acknowledgements

Finder: AXION Security Research Team (Omri Fainaro, Bary Levy): discovery and coordinated disclosure.
