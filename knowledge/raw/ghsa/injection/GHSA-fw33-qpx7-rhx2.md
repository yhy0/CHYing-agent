# gardenctl is vulnerable to Command Injection when used with non‑POSIX shells

**GHSA**: GHSA-fw33-qpx7-rhx2 | **CVE**: CVE-2025-67508 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/gardener/gardenctl-v2** (go): < 0.0.0-20251107111549-0bdc484cb5fb

## Description

A security vulnerability was discovered in [gardenctl](https://github.com/gardener/gardenctl-v2) when it is used with non‑POSIX shells such as **[Fish](https://fishshell.com/)** and **[PowerShell](https://learn.microsoft.com/en-us/powershell/)**. Such setup could allow an attacker with administrative privileges for a Gardener project to craft malicious credential values in infrastructure Secret objects that break out of the intended string context when evaluated in Fish or PowerShell environments used by the Gardener service operators, leading to arbitrary command execution on the operator's device.

**Am I vulnerable?**
This CVE affects all Gardener operators who use  **gardenctl < v2.12.0** with non‑POSIX shells such as **[Fish](https://fishshell.com/)** and **[PowerShell](https://learn.microsoft.com/en-us/powershell/)**.
