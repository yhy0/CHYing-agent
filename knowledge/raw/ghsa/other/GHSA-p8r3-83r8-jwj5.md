# Pterodactyl Wings contains UNIX Symbolic Link (Symlink) Following

**GHSA**: GHSA-p8r3-83r8-jwj5 | **CVE**: CVE-2023-25152 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-59, CWE-61

**Affected Packages**:
- **github.com/pterodactyl/wings** (go): >= 1.11.0, < 1.11.3
- **github.com/pterodactyl/wings** (go): < 1.7.3

## Description

### Impact

This vulnerability impacts anyone running the affected versions of Wings.  The vulnerability can be used to create new files and on the host system that previously did not exist, potentially allowing attackers to change their resource allocations, promote their containers to privileged mode, or potentially add ssh authorized keys to allow the attacker access to a remote shell on the target machine.

In order to use this exploit, an attacker must have an existing "server" allocated and controlled by Wings.  Information on how the exploitation of this vulnerability works will be released on February 24th, 2023 in North America.

### Patches

This vulnerability has been resolved in version `v1.11.3` of Wings, and has been back-ported to the 1.7 release series in `v1.7.3`.

Anyone running `v1.11.x` should upgrade to `v1.11.3` and anyone running `v1.7.x` should upgrade to `v1.7.3`.

### Workarounds

None at this time.
