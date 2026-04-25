# yt-dlp: `--exec` command injection when using `%q` in yt-dlp on Windows (Bypass of CVE-2023-40581)

**GHSA**: GHSA-hjq6-52gw-2g7p | **CVE**: CVE-2024-22423 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-78

**Affected Packages**:
- **yt-dlp** (pip): >= 2021.04.11, < 2024.04.09

## Description

### Summary
The [patch that addressed CVE-2023-40581](https://github.com/yt-dlp/yt-dlp/commit/de015e930747165dbb8fcd360f8775fd973b7d6e) attempted to prevent RCE when using `--exec` with `%q` by replacing double quotes with two double quotes.
However, this escaping is not sufficient, and still allows expansion of environment variables.

Support for output template expansion in `--exec`, along with this vulnerable behavior, was added to `yt-dlp` in version [2021.04.11](https://github.com/yt-dlp/yt-dlp/releases/tag/2021.04.11).

```cmd
> yt-dlp "https://youtu.be/42xO6rVqf2E" --ignore-config -f 18 --exec "echo %(title)q"
[youtube] Extracting URL: https://youtu.be/42xO6rVqf2E
[youtube] 42xO6rVqf2E: Downloading webpage
[youtube] 42xO6rVqf2E: Downloading ios player API JSON
[youtube] 42xO6rVqf2E: Downloading android player API JSON
[youtube] 42xO6rVqf2E: Downloading m3u8 information
[info] 42xO6rVqf2E: Downloading 1 format(s): 18
[download] Destination: %CMDCMDLINE：~-1%&echo pwned&calc.exe [42xO6rVqf2E].mp4
[download] 100% of  126.16KiB in 00:00:00 at 2.46MiB/s
[Exec] Executing command: echo "%CMDCMDLINE:~-1%&echo pwned&calc.exe"
""
pwned
```

### Patches
yt-dlp version 2024.04.09 fixes this issue by properly escaping `%`. It replaces them with `%%cd:~,%`, a variable that expands to nothing, leaving only the leading percent.

### Workarounds
It is recommended to upgrade yt-dlp to version 2024.04.09 as soon as possible. Also, always be careful when using `--exec`, because while this specific vulnerability has been patched, using unvalidated input in shell commands is inherently dangerous.

For Windows users who are not able to upgrade:
- Avoid using any output template expansion in `--exec` other than `{}` (filepath).
- If expansion in `--exec` is needed, verify the fields you are using do not contain `%`, `"`, `|` or `&`.
- Instead of using `--exec`, write the info json and load the fields from it instead.

### Details
When escaping variables, the following code is used for Windows.
[`yt_dlp/compat/__init__.py` line 31-33](https://github.com/yt-dlp/yt-dlp/blob/8e6e3651727b0b85764857fc6329fe5e0a3f00de/yt_dlp/compat/__init__.py#L31-L33)
```python
    def compat_shlex_quote(s):
        import re
        return s if re.match(r'^[-_\w./]+$', s) else s.replace('"', '""').join('""')
```
It replaces `"` with `""` to balance out the quotes and keep quoting intact if non-allowed characters are included. However, the `%CMDCMDLINE%` variable can be used to generate a quote using `%CMDCMDLINE:~-1%`; since the value of `%CMDCMDLINE%` is the commandline with which `cmd.exe` was called, and it is always called with the command surrounded by quotes, `%CMDCMDLINE:~-1%` expands to `"`. After the quotes have been unbalanced, special characters are no longer quoted and commands can be executed:
```cmd
%CMDCMDLINE:~-1%&calc.exe
```

### References
- https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-hjq6-52gw-2g7p
- https://nvd.nist.gov/vuln/detail/CVE-2024-22423
- https://github.com/yt-dlp/yt-dlp/releases/tag/2024.04.09
- https://github.com/yt-dlp/yt-dlp/commit/ff07792676f404ffff6ee61b5638c9dc1a33a37a
