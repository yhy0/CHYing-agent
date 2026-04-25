# soft-serve vulnerable to arbitrary code execution by crafting git-lfs requests

**GHSA**: GHSA-m445-w3xr-vp2f | **CVE**: CVE-2024-41956 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/charmbracelet/soft-serve** (go): < 0.7.5

## Description

### Impact
Any servers using soft-serve server and git

### Patches
>0.7.5

### Workarounds
None.

### References
n/a.

---

It is possible for a user who can commit files to a repository hosted by Soft Serve to execute arbitrary code via environment manipulation and Git.

The issue is that Soft Serve passes all environment variables given by the client to git subprocesses. This includes environment variables that control program execution, such as `LD_PRELOAD`.

This can be exploited to execute arbitrary code by, for example, uploading a malicious shared object file to Soft Serve via Git LFS (uploading it via LFS ensures that it is not compressed on disk and easier to work with). The file will be stored under its SHA256 hash, so it has a predictable name.

This file can then be referenced in `LD_PRELOAD` via a Soft Serve SSH session that causes git to be invoked. For example:

```bash
LD_PRELOAD=/.../data/lfs/1/objects/a2/b5/a2b585befededf5f95363d06d83655229e393b1b45f76d9f989a336668665a2f ssh server git-upload-pack repo
```

The example LFS file patches a shared library function called by git to execute a shell.
