# BuildKit vulnerable to possible race condition with accessing subpaths from cache mounts

**GHSA**: GHSA-m3r6-h7wv-7xxv | **CVE**: CVE-2024-23651 | **Severity**: high (CVSS 8.7)

**CWE**: CWE-362

**Affected Packages**:
- **github.com/moby/buildkit** (go): < 0.12.5

## Description

### Impact
Two malicious build steps running in parallel sharing the same cache mounts with subpaths could cause a race condition that can lead to files from the host system being accessible to the build container.

### Patches
The issue has been fixed in v0.12.5

### Workarounds
Avoid using BuildKit frontend from an untrusted source or building an untrusted Dockerfile containing cache mounts with `--mount=type=cache,source=...` options.

### References
https://www.openwall.com/lists/oss-security/2019/05/28/1

