# TkEasyGUI Vulnerable to OS Command Injection

**GHSA**: GHSA-hfrj-3w3g-jv32 | **CVE**: CVE-2025-55037 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-78

**Affected Packages**:
- **TkEasyGUI** (pip): < 1.0.22

## Description

Improper neutralization of special elements used in an OS command ('OS Command Injection') issue exists in TkEasyGUI versions prior to v1.0.22. If this vulnerability is exploited, an arbitrary OS command may be executed by a remote unauthenticated attacker if the settings are configured to construct messages from external sources.
