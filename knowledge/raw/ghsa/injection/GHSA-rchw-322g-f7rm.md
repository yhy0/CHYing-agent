# osctrl is Vulnerable to OS Command Injection via Environment Configuration

**GHSA**: GHSA-rchw-322g-f7rm | **CVE**: CVE-2026-28279 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/jmpsec/osctrl** (go): < 0.5.0

## Description

### Summary
An OS command injection vulnerability exists in the `osctrl-admin` environment configuration. An authenticated administrator can inject arbitrary shell commands via the hostname parameter when creating or editing environments. These commands are embedded into enrollment one-liner scripts generated using Go's `text/template` package (which does not perform shell escaping) and execute on every endpoint that enrolls using the compromised environment.

### Impact
An attacker with administrator access can achieve remote code execution on every endpoint that enrolls using the compromised environment. Commands execute as root/SYSTEM (the privilege level used for osquery enrollment) before osquery is installed, leaving no agent-level audit trail. This enables backdoor installation, credential exfiltration, and full endpoint compromise.

### Patches
Fixed in osctrl `v0.5.0`. Users should upgrade immediately.

### Workarounds
Restrict osctrl administrator access to trusted personnel. Review existing environment configurations for suspicious hostnames. Monitor enrollment scripts for unexpected commands.

### Credits

Leon Johnson and Kwangyun Keum from TikTok USDS JV Offensive Security Operations (Offensive Privacy Team)

https://github.com/Kwangyun → @Kwangyun
https://github.com/sho-luv → @sho-luv
