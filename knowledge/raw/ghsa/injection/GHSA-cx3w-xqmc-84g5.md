# Git LFS can execute a Git binary from the current directory on Windows

**GHSA**: GHSA-cx3w-xqmc-84g5 | **CVE**: CVE-2021-21237 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-94, CWE-426

**Affected Packages**:
- **github.com/git-lfs/git-lfs** (go): < 2.13.2

## Description

### Impact
On Windows, if Git LFS operates on a malicious repository with a git.bat or git.exe file in the current directory, that program would be executed, permitting the attacker to execute arbitrary code. This does not affect Unix systems.

This is the result of an incomplete fix for CVE-2020-27955.

This issue occurs because on Windows, [Go includes (and prefers) the current directory when the name of a command run does not contain a directory separator](https://github.com/golang/go/issues/38736).

### Patches
This version should be patched in v2.13.2, which will be released in coordination with this security advisory.

### Workarounds
Other than avoiding untrusted repositories or using a different operating system, there is no workaround.

### References
_Are there any links users can visit to find out more?_

### For more information
If you have any questions or comments about this advisory:

- Start a discussion in [the Git LFS discussion page](https://github.com/git-lfs/git-lfs/discussions).
- If you cannot open a discussion, please email the core team using their usernames at `github.com`.
