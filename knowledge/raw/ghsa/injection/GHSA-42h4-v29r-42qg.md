#  yt-dlp on Windows vulnerable to `--exec` command injection when using `%q`

**GHSA**: GHSA-42h4-v29r-42qg | **CVE**: CVE-2023-40581 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-78

**Affected Packages**:
- **yt-dlp** (pip): >= 2021.04.11, < 2023.09.24

## Description

### Impact
[`yt-dlp`](https://github.com/yt-dlp/yt-dlp) allows the user to provide shell commands to be executed at various stages in its download process through the `--exec` flag. This flag allows output template expansion in its argument, so that video metadata values may be used in the shell commands. The metadata fields can be combined with the `%q` conversion, which is intended to quote/escape these values so they can be safely passed to the shell.

However, the escaping used for `cmd` (the shell used by Python's `subprocess` on Windows) did not properly escape special characters, which can allow for remote code execution if `--exec` is used directly with maliciously crafted remote data. This vulnerability only impacts `yt-dlp` on Windows, and the vulnerability is present regardless of whether `yt-dlp` is run from `cmd` or from `PowerShell`.

Support for output template expansion in `--exec`, along with this vulnerable behavior, was added to `yt-dlp` in version [2021.04.11](https://github.com/yt-dlp/yt-dlp/releases/tag/2021.04.11).

```shell
> yt-dlp https://youtu.be/Jo66yyCpHcQ --exec "echo %(title)q"
[youtube] Extracting URL: https://youtu.be/Jo66yyCpHcQ
[youtube] Jo66yyCpHcQ: Downloading webpage
[youtube] Jo66yyCpHcQ: Downloading ios player API JSON
[youtube] Jo66yyCpHcQ: Downloading android player API JSON
[youtube] Jo66yyCpHcQ: Downloading m3u8 information
[info] Jo66yyCpHcQ: Downloading 1 format(s): 135+251
[download] Destination: ＂&echo(&echo(pwned&rem( [Jo66yyCpHcQ].f135.mp4
[download] 100% of    4.85KiB in 00:00:00 at 60.20KiB/s
[download] Destination: ＂&echo(&echo(pwned&rem( [Jo66yyCpHcQ].f251.webm
[download] 100% of    4.80KiB in 00:00:00 at 31.58KiB/s
[Merger] Merging formats into "＂&echo(&echo(pwned&rem( [Jo66yyCpHcQ].mkv"
Deleting original file ＂&echo(&echo(pwned&rem( [Jo66yyCpHcQ].f135.mp4 (pass -k to keep)
Deleting original file ＂&echo(&echo(pwned&rem( [Jo66yyCpHcQ].f251.webm (pass -k to keep)
[Exec] Executing command: echo "\"&echo(&echo(pwned&rem("
"\"

pwned
```

### Patches
yt-dlp version 2023.09.24 fixes this issue by properly escaping each special character.
`\n` will be replaced by `\r`, as no way of escaping it has been found.

### Workarounds
It is recommended to upgrade yt-dlp to version 2023.09.24 as soon as possible. Also, always be careful when using `--exec`, because while this specific vulnerability has been patched, using unvalidated input in shell commands is inherently dangerous.

For Windows users who are not able to upgrade:
- Avoid using any output template expansion in `--exec` other than `{}` (filepath).
- If expansion in `--exec` is needed, verify the fields you are using do not contain `"`, `|` or `&`.
- Instead of using `--exec`, write the info json and load the fields from it instead.

### References
- https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-42h4-v29r-42qg
- https://nvd.nist.gov/vuln/detail/CVE-2023-40581
- https://github.com/yt-dlp/yt-dlp/releases/tag/2023.09.24
- https://github.com/yt-dlp/yt-dlp-nightly-builds/releases/tag/2023.09.24.003044
- https://github.com/yt-dlp/yt-dlp/commit/de015e930747165dbb8fcd360f8775fd973b7d6e
