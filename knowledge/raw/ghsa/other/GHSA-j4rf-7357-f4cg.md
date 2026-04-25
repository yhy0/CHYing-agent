# Unpatched extfs vulnerabilities are exploitable through suid-mode Apptainer

**GHSA**: GHSA-j4rf-7357-f4cg | **CVE**: CVE-2023-30549 | **Severity**: high (CVSS 7.0)

**CWE**: CWE-416

**Affected Packages**:
- **github.com/apptainer/apptainer** (go): < 1.1.8

## Description

### Impact
There is an ext4 use-after-free flaw described in CVE-2022-1184 that is exploitable through versions of Apptainer < 1.1.0 and installations that include apptainer-suid < 1.1.8 on older operating systems where that CVE has not been patched.  That includes Red Hat Enterprise Linux 7, Debian 10 buster (unless the linux-5.10 package is installed), Ubuntu 18.04 bionic and Ubuntu 20.04 focal.  Use-after-free flaws in the kernel can be used to attack the kernel for denial of service and potentially for privilege escalation.

### Background
Historically there have been many CVEs published for extfs and a smaller number for squashfs, including serious use-after-free and buffer overrun vulnerabilities, that are scored as "Moderate" or "Low" impact only because unprivileged users were assumed to not have write access to the raw data.  Because of those ratings, vendors treat such CVEs as low urgency and either delay a patch until their next major release or never patch older but still supported operating systems at all.  Many Linux distributions automatically mount user-writable USB-drive volumes, but those are considered low risk because they require physical access to the machine.  However, since setuid-root installations of Apptainer by default allow all users to mount any extfs (specifically, ext3, which is implemented by the ext4 driver) and squashfs filesystem using kernel drivers even though the users have write access to the raw data, the setuid-root installations raise the severity of such unpatched CVEs.  

CVE-2022-1184 is currently such an unpatched CVE, at least on the above listed operating systems.  The descriptions from the operating system vendors about the CVE (referenced below) are incomplete, saying only that it allows a local attacker with user privilege to cause a denial of service.  Normally users would not be able to cause it because they cannot modify the filesystem image, and normally vulnerabilities that involve kernel memory corruption by unprivileged users are considered high severity even when there is not yet a known privilege escalation because someone with sufficient kernel knowledge can usually turn such a corruption into a privilege escalation. 

Red Hat did not list RHEL7 as vulnerable, but they also did not list it as unaffected, and testing confirmed that a filesystem image could be corrupted to get past the check inserted into the filesystem driver to fix the vulnerability (patches linked below).

All published squashfs CVEs have been patched in currently supported major operating systems.

### Patches
Apptainer 1.1.8 includes a patch that by default disables mounting of extfs filesystem types in setuid-root mode, while continuing to allow mounting of extfs filesystems in non-setuid "rootless" mode using fuse2fs.

### Workarounds
These workarounds are possible:
1. Either do not install apptainer-suid (for versions 1.1.0 through 1.1.7) or set `allow setuid = no` in apptainer.conf.  This requires having unprivileged user namespaces enabled and except for apptainer 1.1.x versions will disallow mounting of sif files, extfs files, and squashfs files in addition to other, less significant impacts.  (Encrypted sif files are also not supported unprivileged in apptainer 1.1.x.)
2. Alternatively, use the `limit containers` options in apptainer.conf/singularity.conf to limit sif files to trusted users, groups, and/or paths.  (The option `allow container extfs = no` disallows mounting extfs overlay files but does not disallow mounting of extfs overlay partitions inside SIF files, so it does not help work around the problem.)

### References
https://nvd.nist.gov/vuln/detail/CVE-2022-1184
https://access.redhat.com/security/cve/cve-2022-1184
https://security-tracker.debian.org/tracker/CVE-2022-1184
https://ubuntu.com/security/CVE-2022-1184
Kernel patches for CVE-2022-1184:
https://github.com/torvalds/linux/commit/65f8ea4cd57dbd46ea13b41dc8bac03176b04233
https://github.com/torvalds/linux/commit/61a1d87a324ad5e3ed27c6699dfc93218fcf3201

------

## Addendum 30 May 2023

New information has become available: many ext4 filesytem vulnerabilities similar to the one in CVE-2022-1184 continue to be found, and most of them do not ever have a CVE assigned.  The way to locate them is to search for "syzbot" in linux kernel commit messages under fs/ext4.  "syzbot" is a public automated system for finding kernel bugs.  Especially when syzbot reports are labeled "KASAN" (Kernel Address Sanitizer) and especially if they involve memory corruption including "use after free", "out of bounds", or "user-memory-access", they are vulnerabilities that can potentially be turned into privilege escalation when an unprivileged user has write access to the underlying data.

In particular there are two such commits from this month, May 2023, referenced below.  They both have commit messages describing a situation of write access to the underlying data while the kernel has that data mounted as a filesystem.  These commits have been backported to currently maintained kernel lines in versions 4.19.293 and 5.4.243, but since they are considered moderate severity, most common OS distributions do not include them immediately.  For example since RHEL9.2 was recently announced, they are not likely to be available in RHEL9 until 9.3 is released in about another 6 months.  Therefore if system administrators want to be protected against these vulnerabilities while still allowing ext4 filesystem mounts through setuid-root apptainer, they should watch for these types of commits and whenever such commits are released the administrators should update to the latest currently maintained kernel version (bypassing their OS vendor's distribution) and reboot.

https://github.com/torvalds/linux/commit/2220eaf90992c11d888fe771055d4de3303
https://github.com/torvalds/linux/commit/4f04351888a83e595571de672e0a4a8b74f
https://lwn.net/Articles/932137/
https://lwn.net/Articles/932136/
