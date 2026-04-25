# Picklescan is Vulnerable to Unsafe Globals Check Bypass through Subclass Imports

**GHSA**: GHSA-f7qq-56ww-84cr | **CVE**: CVE-2025-10157 | **Severity**: critical (CVSS 8.3)

**CWE**: CWE-693

**Affected Packages**:
- **picklescan** (pip): <= 0.0.30

## Description

### Summary
The vulnerability allows malicious actors to bypass PickleScan's unsafe globals check, leading to potential arbitrary code execution. The issue stems from PickleScan's strict check for full module names against its list of unsafe globals. By using subclasses of dangerous imports instead of the exact module names, attackers can circumvent the check and inject malicious payloads.

### PoC
1. Download a model that uses the `asyncio` package: 

```wget https://huggingface.co/iluem/linux_pkl/resolve/main/asyncio_asyncio_unix_events___UnixSubprocessTransport__start.pkl```

2. Check with PickleScan: `picklescan -p asyncio_asyncio_unix_events___UnixSubprocessTransport__start.pkl -g`

**Expected Result:**

PickleScan should identify all `asyncio` import as dangerous and flag the pickle file as malicious as `asyncio` is in `_unsafe_globals` dictionary.

**Actual Result:**
![Screenshot 2025-06-29 at 14 13 38](https://github.com/user-attachments/assets/39467f50-5cdb-4c25-bb37-35c03dc4a626)

PickleScan marked the import as Suspicious, failing to identify it as a dangerous import.

### Impact
**Severity**: High
**Affected Users**: Any organization, like HuggingFace, or individual using PickleScan to analyze PyTorch models or other files distributed as ZIP archives for malicious pickle content.
**Impact Details**: Attackers can craft malicious PyTorch models containing embedded pickle payloads, package them into ZIP archives, and bypass the PickleScan check by using subclasses of dangerous imports. This could lead to arbitrary code execution on the user's system when these malicious files are processed or loaded.

**Recommendations:**

**Replace:**
https://github.com/mmaitre314/picklescan/blob/2a8383cfeb4158567f9770d86597300c9e508d0f/src/picklescan/scanner.py#L309C9-L309C54


  `      unsafe_filter = _unsafe_globals.get(g.module)`

by:
```
      matched_key = None
        if imported_global.module:
            for key_in_globals in unsafe_globals.keys():
                # Check if imported_global.module starts with the key_in_globals AND
                # (it's the first match OR this key is more specific than the previous match)
                # AND imported_global.module is exactly the key or imported_global.module is key + '.' + something
                if imported_global.module.startswith(key_in_globals):
                    if (imported_global.module == key_in_globals or # Exact match
                            (len(imported_global.module) > len(key_in_globals) and imported_global.module[len(key_in_globals)] == '.')): # Submodule match
                        if matched_key is None or len(key_in_globals) > len(matched_key):
                            matched_key = key_in_globals

        if matched_key:
            unsafe_filter = unsafe_globals[matched_key]
```
