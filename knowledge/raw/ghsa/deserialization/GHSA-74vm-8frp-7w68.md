# EPyT-Flow vulnerable to unsafe JSON deserialization (__type__)

**GHSA**: GHSA-74vm-8frp-7w68 | **CVE**: CVE-2026-25632 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-502

**Affected Packages**:
- **epyt-flow** (pip): < 0.16.1

## Description

### Impact
EPyT-Flow’s REST API parses attacker-controlled JSON request bodies using a custom deserializer (my_load_from_json) that supports a __type__ field. When __type__ is present, the deserializer dynamically imports an attacker-specified module/class and instantiates it with attacker-supplied arguments. This allows invoking dangerous classes such as subprocess.Popen, which can lead to OS command execution during JSON parsing. This also affects the loading of JSON files.

### Patches
EPyT-Flow  has been patched in 0.16.1 -- affects all versions <= 0.16.0

### Workarounds
Do not load any JSON from untrusted sources and do not expose the REST API.

### Credits
EPyT-Flow  thanks Jarrett Chan (@syphonetic) for detecting and reporting the bug.
