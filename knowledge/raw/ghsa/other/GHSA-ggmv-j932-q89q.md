# Chall-Manager's HTTP Gateway is vulnerable to DoS due to missing header timeout

**GHSA**: GHSA-ggmv-j932-q89q | **CVE**: CVE-2025-53634 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/ctfer-io/chall-manager** (go): < 0.1.4

## Description

### Impact
The HTTP Gateway processes headers, but with no timeout set. With a Slowloris attack, an attacker could cause Denial of Service (DoS).
Exploitation does not require authentication nor authorization, so anyone can exploit it. It should nonetheless not be exploitable as it is highly recommended to bury Chall-Manager deep within the infrastructure due to its large capabilities, so no users could reach the system.

### Patches
Patch has been implemented by [commit `1385bd8`](https://github.com/ctfer-io/chall-manager/commit/1385bd869142651146cd0b123085f91cec698636) and shipped in [`v0.1.4`](https://github.com/ctfer-io/chall-manager/releases/tag/v0.1.4).

### Workarounds
No workaround exist.

### References
N/A
