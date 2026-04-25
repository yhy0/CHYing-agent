# yt-dlp: Arbitrary Command Injection when using the `--netrc-cmd` option

**GHSA**: GHSA-g3gw-q23r-pgqm | **CVE**: CVE-2026-26331 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-78

**Affected Packages**:
- **yt-dlp** (pip): >= 2023.06.21, < 2026.02.21

## Description

### Summary
When yt-dlp's `--netrc-cmd` command-line option (or `netrc_cmd` Python API parameter) is used, an attacker could achieve arbitrary command injection on the user's system with a maliciously crafted URL.

### Impact
yt-dlp maintainers assume the impact of this vulnerability to be high for anyone who uses `--netrc-cmd` in their command/configuration or `netrc_cmd` in their Python scripts. Even though the maliciously crafted URL itself will look very suspicious to many users, it would be trivial for a maliciously crafted webpage with an inconspicuous URL to covertly exploit this vulnerability via HTTP redirect. Users without `--netrc-cmd` in their arguments or `netrc_cmd` in their scripts are unaffected. No evidence has been found of this exploit being used in the wild.

### Patches
yt-dlp version 2026.02.21 fixes this issue by validating all netrc "machine" values and raising an error upon unexpected input.

### Workarounds
It is recommended to upgrade yt-dlp to version 2026.02.21 as soon as possible.

Users who are unable to upgrade should avoid using the `--netrc-cmd` command-line option (or `netrc_cmd` Python API parameter), or they should at least not pass a placeholder (`{}`) in their `--netrc-cmd` argument.

### Details
yt-dlp's `--netrc-cmd` option can be used to run any arbitrary shell command to retrieve site login credentials so that the user doesn't have to store the credentials as plaintext in the filesystem. The `--netrc-cmd` argument is a shell command with an optional placeholder (`{}`). If the placeholder is present in the argument, it is replaced with the netrc "machine" value, which specifies the site for which login credentials are needed.

The netrc "machine" value is usually explicitly defined in yt-dlp's extractor code for a given site. However, yt-dlp has four extractors where the netrc "machine" value needs to be dynamically sourced from the site's hostname. And in three of those extractors (`GetCourseRuIE`, `TeachableIE` and `TeachableCourseIE`), wildcard matches are allowed for one or more subdomains of the hostname. This can result in a netrc "machine" value that contains special shell characters.

The `--netrc-cmd` argument is executed by a modified version of Python's `subprocess.Popen` with `shell=True`, which means that any special characters may be interpreted by the host shell, potentially leading to arbitrary command injection.

Here is an example of maliciously crafted URL input that exploits the vulnerability:

```cmd
> yt-dlp --netrc-cmd "echo {}" "https://;echo pwned>&2;#.getcourse.ru/video"
[GetCourseRu] Executing command: echo getcourseru
WARNING: [GetCourseRu] Failed to parse .netrc: bad toplevel token 'getcourseru' (-, line 2)
[GetCourseRu] Extracting URL: https://;echo pwned>&2;#.getcourse.ru/video
[GetCourseRu] Executing command: echo ;echo pwned>&2;
pwned
[GetCourseRu] No authenticators for ;echo pwned>&2;
[GetCourseRu] video: Downloading webpage
```

Although only 3 of yt-dlp's extractors are directly susceptible to this attack, yt-dlp's "generic" extractor will follow HTTP redirects and try to match the resulting URL with one of the dedicated extractors. This means that any URL processed by the generic extractor could ultimately lead to a maliciously crafted URL that is matched by one of the vulnerable extractors. Hypothetically, an attacker could create a website with an inconspicuous URL and legitimate-looking media content that would serve an HTTP redirect to a maliciously crafted URL when it detects a request from yt-dlp.


### References
- https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-g3gw-q23r-pgqm
- https://nvd.nist.gov/vuln/detail/CVE-2026-26331
- https://github.com/yt-dlp/yt-dlp/releases/tag/2026.02.21
- https://github.com/yt-dlp/yt-dlp/commit/1fbbe29b99dc61375bf6d786f824d9fcf6ea9c1a
