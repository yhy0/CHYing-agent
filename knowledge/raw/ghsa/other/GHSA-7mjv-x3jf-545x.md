# cloudflared's Installer has Local Privilege Escalation Vulnerability

**GHSA**: GHSA-7mjv-x3jf-545x | **CVE**: CVE-2023-1314 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-59

**Affected Packages**:
- **github.com/cloudflare/cloudflared** (go): < 0.0.0-20230313153246-f686da832f85

## Description

### Impact

A vulnerability has been discovered in cloudflared's installer (<= 2023.3.0) for Windows 32-bits devices that allows a local attacker with no administrative permissions to escalate their privileges on the affected device. This vulnerability exists because the MSI installer used by cloudflared relied on a world-writable directory.

An attacker with local access to the device (without Administrator rights) can use symbolic links to trick the MSI installer into deleting files in locations that the attacker would otherwise have no access to. By creating a symlink from the world-writable directory to the target file, the attacker can manipulate the MSI installer's repair functionality to delete the target file during the repair process.

Exploitation of this vulnerability could allow an attacker to delete important system files or replace them with malicious files, potentially leading to the affected device being compromised.

**The cloudflared client itself is not affected by this vulnerability, only the installer for 32-bit Windows devices.**

### Patches
A new installer was released as part of version 2023.3.1, corresponding to pseudoversion 0.0.0-20230313153246-f686da832f85 on pkg.go.dev. Users are encouraged to remove old installers from their systems.

### References
[Cloudflared Releases](https://github.com/cloudflare/cloudflared/releases)
