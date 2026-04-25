# AstrBot is vulnerable to RCE with hard-coded JWT signing keys

**GHSA**: GHSA-4m32-cjv7-f425 | **CVE**: CVE-2025-55449 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-345, CWE-798

**Affected Packages**:
- **astrbot** (pip): < 3.5.18

## Description

### Summary
AstrBot uses a hard-coded JWT signing key, allowing attackers to execute arbitrary commands by installing a malicious plugin.

### Details

AstrBot uses a [hard-coded JWT signing key](https://github.com/AstrBotDevs/AstrBot/blob/v3.5.16/astrbot/core/__init__.py), which allows attackers to bypass the authentication mechanism. Once bypassed, the attacker can install a Python plugin that will be imported [here](https://github.com/AstrBotDevs/AstrBot/blob/master/astrbot/dashboard/routes/plugin.py), enabling arbitrary command execution on the target host.

### Impact

All publicly accessible AstrBot instances are vulnerable.

For more information, please see: [CVE-2025-55449-AstrBot-RCE](https://github.com/Marven11/CVE-2025-55449-AstrBot-RCE)

### Patch

This vulnerability was first reported on **2025-06-21** and was patched on the **same day** (2025-06-21).

The vulnerability was publicly disclosed on **2025-11-14**. Prior to public disclosure, monitoring from AstrBot Cloud indicated that fewer than 2% of deployed instances were still running the affected version. Therefore, this disclosure is not expected to have a significant impact on existing active instances.
