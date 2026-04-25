# Git LFS can execute a Git binary from the current directory

**GHSA**: GHSA-4g4p-42wc-9f3m | **CVE**: CVE-2020-27955 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-427

**Affected Packages**:
- **github.com/git-lfs/git-lfs** (go): < 2.12.1

## Description

### Impact
On Windows, if Git LFS operates on a malicious repository with a `git.bat` or `git.exe` file in the current directory, that program would be executed, permitting the attacker to execute arbitrary code.  This does not affect Unix systems.

This occurs because on Windows, Go includes (and prefers) the current directory when the name of a command run does not contain a directory separator.

### Patches
This version should be patched in v2.12.1, which will be released in coordination with this security advisory.

### Workarounds
Other than avoiding untrusted repositories, there is no workaround.

### For more information
If you have any questions or comments about this advisory:
* Start a discussion in [the Git LFS discussion page](https://github.com/git-lfs/git-lfs/discussions).
* If you cannot open a discussion, please email the core team using their usernames at `github.com`.

