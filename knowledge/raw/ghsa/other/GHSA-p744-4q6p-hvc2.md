# Wings vulnerable to escape to host from installation container

**GHSA**: GHSA-p744-4q6p-hvc2 | **CVE**: CVE-2023-32080 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-250

**Affected Packages**:
- **github.com/pterodactyl/wings** (go): < 1.7.5
- **github.com/pterodactyl/wings** (go): >= 1.11.0, < 1.11.6

## Description

### Impact

This vulnerability impacts anyone running the affected versions of Wings.  This vulnerability can be used to gain access to the host system running Wings if a user is able to modify an server's install script or the install script executes code supplied by the user (either through environment variables, or commands that execute commands based off of user data).

### Patches

This vulnerability has been resolved in version `v1.11.6` of Wings, and has been back-ported to the 1.7 release series in `v1.7.5`.

Anyone running `v1.11.x` should upgrade to `v1.11.6` and anyone running `v1.7.x` should upgrade to `v1.7.5`.

### Workarounds

Running Wings with a rootless container runtime may mitigate the severity of any attacks, however the majority of users are using container runtimes that run as root as per our documentation.

SELinux may prevent attackers from performing certain operations against the host system, however privileged containers have a lot of freedom even on systems with SELinux enabled.

TL;DR: None at this time.

### Extra details

It should be noted that this was a known attack vector, for attackers to easily exploit this attack it would require compromising an administrator account on a Panel.  However, certain eggs (the data structure that holds the install scripts that get passed to Wings) have an issue where they are unknowingly executing shell commands with escalated privileges provided by untrusted user data.
