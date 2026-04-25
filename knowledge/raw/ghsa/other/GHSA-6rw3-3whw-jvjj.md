# Git LFS can execute a binary from the current directory on Windows

**GHSA**: GHSA-6rw3-3whw-jvjj | **CVE**: CVE-2022-24826 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-426

**Affected Packages**:
- **github.com/git-lfs/git-lfs/v3** (go): >= 3.0.0, < 3.1.3
- **github.com/git-lfs/git-lfs** (go): >= 2.12.1

## Description

### Impact
On Windows, if Git LFS operates on a malicious repository with a `..exe` file as well as a file named `git.exe`, and `git.exe` is not found in `PATH`, the `..exe` program will be executed, permitting the attacker to execute arbitrary code.  This does not affect Unix systems.

Similarly, if the malicious repository contains files named `..exe` and `cygpath.exe`, and `cygpath.exe` is not found in `PATH`, the `..exe` program will be executed when certain Git LFS commands are run.

More generally, if the current working directory contains any file with a base name of `.` and a file extension from `PATHEXT` (except `.bat` and `.cmd`), and also contains another file with the same base name as a program Git LFS intends to execute (such as `git`, `cygpath`, or `uname`) and any file extension from `PATHEXT` (including `.bat` and `.cmd`), then, on Windows, when Git LFS attempts to execute the intended program the `..exe`, `..com`, etc., file will be executed instead, but only if the intended program is not found in any directory listed in `PATH`.

The vulnerability occurs because when Git LFS detects that the program it intends to run does not exist in any directory listed in `PATH` then Git LFS passes an empty string as the executable file path to the Go `os/exec` package, which contains a bug such that, on Windows, it prepends the name of the current working directory (i.e., `.`) to the empty string without adding a path separator, and as a result searches in that directory for a file with the base name `.` combined with any file extension from `PATHEXT`, executing the first one it finds.

(The reason `..bat` and `..cmd` files are not executed in the same manner is that, although the Go `os/exec` package tries to execute them just as it does a `..exe` file, the Microsoft Win32 API `CreateProcess()` family of functions have an undocumented feature in that they apparently recognize when a caller is attempting to execute a batch script file and instead run the `cmd.exe` command interpreter, passing the full set of command line arguments as parameters.  These are unchanged from the command line arguments set by Git LFS, and as such, the intended program's name is the first, resulting in a command line like `cmd.exe /c git`, which then fails.)

Git LFS has resolved this vulnerability by always reporting an error when a program is not found in any directory listed in `PATH` rather than passing an empty string to the Go `os/exec` package in this case.

The bug in the Go `os/exec` package has been reported to the Go project and is expected to be patched after this security advisory is published.

### Patches
The problem was introduced in v2.12.1 and is patched in v3.1.3 and v3.1.4.  Users of affected versions should upgrade to v3.1.4.

### Workarounds
There are no known workarounds at this time.

### References
* https://github.com/git-lfs/git-lfs/security/advisories/GHSA-6rw3-3whw-jvjj
* https://nvd.nist.gov/vuln/detail/CVE-2022-24826
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24826
* https://github.com/git-lfs/git-lfs/releases/tag/v3.1.4
* [git-lfs/git-lfs@762ccd4a49](https://github.com/git-lfs/git-lfs/commit/762ccd4a498f5c17723b91d56b9304434ada5540)

### For more information
If you have any questions or comments about this advisory:
* For general questions, start a discussion in the Git LFS [discussion forum](https://github.com/git-lfs/git-lfs/discussions).
* For reports of additional vulnerabilities, please follow the Git LFS [security reporting policy](https://github.com/git-lfs/git-lfs/blob/main/SECURITY.md).
