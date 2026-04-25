# AutoGPT bypass of the shell commands denylist settings

**GHSA**: GHSA-g84q-54hf-36rg | **CVE**: CVE-2024-6091 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-78

**Affected Packages**:
- **agpt** (pip): <= 0.5.1

## Description

A vulnerability in significant-gravitas/autogpt version 0.5.1 allows an attacker to bypass the shell commands denylist settings. The issue arises when the denylist is configured to block specific commands, such as `whoami` and `/bin/whoami`. An attacker can circumvent this restriction by executing commands with a modified path, such as `/bin/./whoami`, which is not recognized by the denylist.
