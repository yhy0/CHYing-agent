# goshs route not protected, allows command execution

**GHSA**: GHSA-rwj2-w85g-5cmm | **CVE**: CVE-2025-46816 | **Severity**: critical (CVSS 9.4)

**CWE**: CWE-77, CWE-284

**Affected Packages**:
- **github.com/patrickhener/goshs** (go): >= 0.3.4, <= 1.0.4

## Description

### Summary

It seems that when running **goshs** without arguments it is possible for anyone to execute commands on the server. This was tested on version **1.0.4** of **goshs**. The command function was introduced in version **0.3.4**.

### Details

It seems that the function ```dispatchReadPump``` does not checks the option cli ```-c```, thus allowing anyone to execute arbitrary command through the use of websockets.

### PoC

Used **websocat** for the POC:
```bash
echo -e '{"type": "command", "content": "id"}' |./websocat 'ws://192.168.1.11:8000/?ws' -t
```

### Impact

The vulnerability will only impacts goshs server on vulnerable versions.
